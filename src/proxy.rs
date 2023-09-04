use crate::app::{AppState, AppStateInner, UpstreamConfig};
use crate::auth::AuthorizeParams;
use crate::http::{Cookies, SetCookie};
use crate::uri::UriBuilder;
use crate::utils::Duration;

use std::str::FromStr;

use axum::extract::{FromRequestParts, OriginalUri};
use axum::{
    extract::{FromRequest, Host, Query, State},
    http::{
        header::{HeaderValue, AUTHORIZATION},
        Request, StatusCode, Uri,
    },
    middleware::Next,
    response::{IntoResponse, Redirect, Response},
};
use cookie::Cookie;
use hyper::{client::HttpConnector, Body};
use hyper_tls::HttpsConnector;
use log::{error, info, warn};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};

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
    hostname: String,
    upstream_uri: Uri,
    origin: String,
}

const COOKIE_NAME: &str = "_identity.im";

#[derive(Serialize, Deserialize)]
pub struct UpstreamAuthorizeParams {
    pub token: String,
    pub redirect_to: String,
}

impl ProxyClient {
    pub fn new(cfg: &UpstreamConfig) -> anyhow::Result<Self> {
        let hostname = cfg.upstream_url.host_str().unwrap().into();

        let https = HttpsConnector::new();
        let client = hyper::Client::builder().build::<_, Body>(https);

        let upstream_uri = Uri::from_str(cfg.upstream_url.as_str())?;

        let origin = cfg.origin_url.origin().ascii_serialization();

        Ok(Self {
            config: cfg.clone(),
            client,
            hostname,
            upstream_uri,
            origin,
        })
    }

    pub fn name(&self) -> &str {
        self.config.name.as_str()
    }

    pub fn origin(&self) -> &str {
        self.origin.as_str()
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

        Ok(self.redirect_to_authorization(request, state).await)
    }

    async fn authorize(
        &self,
        request: Request<Body>,
        state: &AppStateInner,
    ) -> anyhow::Result<impl IntoResponse> {
        let query = Query::<UpstreamAuthorizeParams>::from_request(request, state).await?;

        Ok((
            SetCookie(
                Cookie::build(COOKIE_NAME, query.token.clone())
                    .path("/")
                    .http_only(true)
                    .max_age((*PROXY_TOKEN_TTL).into())
                    .finish(),
            ),
            Redirect::to(query.redirect_to.as_str()),
        ))
    }

    async fn resolve_full_url<B>(&self, request: Request<B>, state: &AppStateInner) -> String {
        let (mut parts, _) = request.into_parts();
        let host = Host::from_request_parts(&mut parts, state).await;
        let OriginalUri(uri) = OriginalUri::from_request_parts(&mut parts, state)
            .await
            .unwrap();

        let scheme = uri
            .scheme_str()
            .unwrap_or(self.config.origin_url.scheme());

        match (host, uri.path_and_query()) {
            (Ok(host), Some(path_and_query)) => {
                if path_and_query.path().starts_with('/') {
                    format!("{}://{}{}", scheme, host.0, path_and_query)
                } else {
                    format!("{}://{}/{}", scheme, host.0, path_and_query)
                }
            }
            _ => format!("{}", uri),
        }
    }

    async fn redirect_to_authorization<B>(
        &self,
        request: Request<B>,
        state: &AppStateInner,
    ) -> Response
    where
        B: Send + 'static,
    {
        let full_uri = self.resolve_full_url(request, state).await;
        let redirect_uri = UriBuilder::from_str(state.config.base_url.as_str())
            .unwrap()
            .append_path("/authorize")
            .append_params(AuthorizeParams {
                client_id: self.config.name.to_string(),
                redirect_to: full_uri,
            })
            .to_string();

        Redirect::to(redirect_uri.as_str()).into_response()
    }

    async fn forward(&self, mut request: Request<Body>) -> anyhow::Result<Response> {
        let mut parts = self.upstream_uri.clone().into_parts();
        parts.path_and_query = request.uri().path_and_query().cloned();
        let uri = Uri::from_parts(parts)?;

        info!("Forwarding {} to {}", request.uri(), uri);
        *request.uri_mut() = uri;

        Ok(self.client.request(request).await?.into_response())
    }
}
