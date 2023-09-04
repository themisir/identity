use crate::app::{AppState, AppStateInner, UpstreamConfig};
use crate::http::{Cookies, SetCookie, UriQueryBuilder};
use axum::extract::path::ErrorKind;
use axum::extract::{FromRequest, Query};
use axum::http::header::AUTHORIZATION;
use axum::http::uri::{InvalidUriParts, PathAndQuery};
use axum::response::Redirect;
use axum::{
    extract::{Host, State},
    http::{uri, Request, StatusCode, Uri},
    middleware::Next,
    response::{IntoResponse, Response},
};
use cookie::Cookie;
use hyper::header::HeaderValue;
use hyper::{client::HttpConnector, Body};
use hyper_tls::HttpsConnector;
use log::{error, info, warn};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use crate::utils::Duration;

pub async fn middleware(
    State(state): State<AppState>,
    Host(host): Host,
    request: Request<Body>,
    next: Next<Body>,
) -> Result<Response, StatusCode> {
    let state = state.read().await;
    let upstream = {
        let host = host.to_lowercase();
        state.upstreams.find_by_host(host.as_str())
    };

    match upstream {
        None => Ok(next.run(request).await),
        Some(client) => client.handle(request, &state).await.map_err(|err| {
            error!(
                "[{}] failed to handle proxy request: {}",
                client.name(),
                err
            );
            StatusCode::SERVICE_UNAVAILABLE
        }),
    }
}

pub const PROXY_AUTHORIZE_ENDPOINT: &str = "/.identity/authorize";
pub static PROXY_TOKEN_TTL: Lazy<Duration> = Lazy::new(|| Duration::minutes(5));

pub struct ProxyClient {
    config: UpstreamConfig,
    client: hyper::Client<HttpsConnector<HttpConnector>>,
    host: Uri,
}

const COOKIE_NAME: &str = "_identity.im";

#[derive(Serialize, Deserialize)]
struct AuthorizeQuery {
    token: String,
    redirect_to: Option<String>,
}

impl ProxyClient {
    pub fn new(config: &UpstreamConfig) -> anyhow::Result<Self> {
        info!(
            "create upstream client {} for {}",
            config.name, config.hostname
        );

        let https = HttpsConnector::new();
        let client = hyper::Client::builder().build::<_, hyper::Body>(https);
        let host = Uri::from_str(config.target_url.as_str())?;

        Ok(Self {
            config: config.clone(),
            client,
            host,
        })
    }

    pub fn name(&self) -> &str {
        self.config.name.as_str()
    }

    pub fn host(&self) -> &Uri {
        &self.host
    }

    pub async fn handle(
        &self,
        mut request: Request<Body>,
        state: &AppStateInner,
    ) -> anyhow::Result<Response> {
        if request.uri().path() == PROXY_AUTHORIZE_ENDPOINT {
            return Ok(self.authorize(request, state).await?.into_response());
        }

        if let Some(cookie) = Cookies::extract_one(request.headers(), COOKIE_NAME) {
            if let Err(err) = state.issuer.validate_token(cookie.value()) {
                warn!("token validation failed: {}", err);
            } else {
                let value: HeaderValue = format!("Bearer {}", cookie.value()).try_into()?;

                request.headers_mut().append(AUTHORIZATION, value);

                return self.forward(request).await;
            }
        }

        Ok(self.redirect_to_authorization(&request, state))
    }

    async fn authorize(
        &self,
        request: Request<Body>,
        state: &AppStateInner,
    ) -> anyhow::Result<impl IntoResponse> {
        let query = Query::<AuthorizeQuery>::from_request(request, state).await?;
        let redirect_to = match &query.redirect_to {
            None => "",
            Some(s) => s.as_str(),
        };

        Ok((
            SetCookie(
                Cookie::build(COOKIE_NAME, query.token.clone())
                    .path("/")
                    .http_only(true)
                    .max_age((*PROXY_TOKEN_TTL).into())
                    .finish(),
            ),
            Redirect::to(redirect_to),
        ))
    }

    fn redirect_to_authorization<B>(
        &self,
        request: &Request<B>,
        state: &AppStateInner,
    ) -> Response {
        Redirect::to(
            UriQueryBuilder::new(format!("{}/login?", state.config.base_url))
                .append("client_id", &self.config.name)
                .append("redirect_to", request.uri().to_string())
                .build()
                .as_str(),
        )
        .into_response()
    }

    pub fn upstream_uri(&self, path_and_query: Option<PathAndQuery>) -> anyhow::Result<Uri> {
        let mut parts = self.host.clone().into_parts();
        parts.path_and_query = path_and_query;
        Ok(Uri::from_parts(parts)?)
    }

    async fn forward(&self, mut request: Request<Body>) -> anyhow::Result<Response> {
        let mut parts = self.host.clone().into_parts();
        parts.path_and_query = request.uri().path_and_query().map(uri::PathAndQuery::clone);

        let uri = self.upstream_uri(request.uri().path_and_query().cloned())?;
        info!("Forwarding {} to {}", request.uri(), uri);
        *request.uri_mut() = uri;

        Ok(self.client.request(request).await?.into_response())
    }
}
