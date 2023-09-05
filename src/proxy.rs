use crate::app::{AppState, UpstreamConfig};
use crate::auth::AuthorizeParams;
use crate::http::{Cookies, SetCookie};
use crate::uri::UriBuilder;
use crate::utils::Duration;

use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use crate::store::UserClaim;
use axum::{
    extract::{FromRequest, FromRequestParts, Host, OriginalUri, Query, State},
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
    let upstream = {
        let host = host.to_lowercase();
        state.upstreams().find_by_host(host.as_str())
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
    upstream_uri: Uri,
    origin: String,
    claims: HashSet<String>,
}

const COOKIE_NAME: &str = "_identity.im";

#[derive(Serialize, Deserialize)]
pub struct UpstreamAuthorizeParams {
    pub token: String,
    pub redirect_to: String,
}

impl ProxyClient {
    pub fn new(cfg: &mut UpstreamConfig) -> anyhow::Result<Self> {
        let https = HttpsConnector::new();
        let client = hyper::Client::builder().build::<_, Body>(https);

        let upstream_uri = Uri::from_str(cfg.upstream_url.as_str())?;

        let origin = cfg.origin_url.origin().ascii_serialization();

        let claims = HashSet::from_iter(cfg.claims.clone());

        if let Some(require_claims) = &cfg.require_claims {
            if require_claims.is_empty() {
                cfg.require_claims = None;
            } else {
                if !cfg.require_authentication {
                    anyhow::bail!("Upstream '{}' required claims, but does not require authentication. Please set require_authentication to true on the upstream configuration", cfg.name);
                }

                for claim in require_claims {
                    if !claims.contains(claim.as_str()) {
                        anyhow::bail!("Required claim '{}' is not available for the upstream '{}'. Please add the claim to claims section of the upstream configuration", claim, cfg.name);
                    }
                }
            }
        }

        Ok(Self {
            config: cfg.clone(),
            client,
            upstream_uri,
            origin,
            claims,
        })
    }

    pub fn name(&self) -> &str {
        self.config.name.as_str()
    }

    pub fn origin(&self) -> &str {
        self.origin.as_str()
    }

    pub fn filter_claims(&self, claims: Vec<UserClaim>) -> Option<Vec<UserClaim>> {
        if let Some(required_claims) = &self.config.require_claims {
            let filtered_claims: HashMap<String, UserClaim> = claims
                .into_iter()
                .filter(|c| self.claims.contains(c.name.as_str()))
                .map(|c| (c.name.clone(), c))
                .collect();

            for claim in required_claims {
                if !filtered_claims.contains_key(claim.as_str()) {
                    warn!("required claim '{}' is missing", claim);
                    return None;
                }
            }

            Some(filtered_claims.into_values().collect())
        } else {
            Some(
                claims
                    .into_iter()
                    .filter(|c| self.claims.contains(&c.name))
                    .collect(),
            )
        }
    }

    pub async fn handle(
        &self,
        mut request: Request<Body>,
        state: &AppState,
    ) -> anyhow::Result<Response> {
        if request.uri().path() == PROXY_AUTHORIZE_ENDPOINT {
            return Ok(self.authorize(request, state).await?.into_response());
        }

        if let Some(cookie) = Cookies::extract_one(request.headers(), COOKIE_NAME) {
            if let Err(err) = state.issuer().validate_token(cookie.value()) {
                warn!("token validation failed: {}", err);
            } else {
                let value: HeaderValue = format!("Bearer {}", cookie.value()).try_into()?;

                request.headers_mut().append(AUTHORIZATION, value);

                return self.forward(request).await;
            }
        }

        if self.config.require_authentication {
            Ok(self.redirect_to_authorization(request, state).await)
        } else {
            self.forward(request).await
        }
    }

    async fn authorize(
        &self,
        request: Request<Body>,
        state: &AppState,
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

    async fn resolve_full_url<B>(&self, request: Request<B>, state: &AppState) -> String {
        let (mut parts, _) = request.into_parts();
        let host = Host::from_request_parts(&mut parts, state).await;
        let OriginalUri(uri) = OriginalUri::from_request_parts(&mut parts, state)
            .await
            .unwrap();

        let scheme = uri.scheme_str().unwrap_or(self.config.origin_url.scheme());

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

    async fn redirect_to_authorization<B>(&self, request: Request<B>, state: &AppState) -> Response
    where
        B: Send + 'static,
    {
        let full_uri = self.resolve_full_url(request, state).await;
        let redirect_uri = UriBuilder::from_url(&state.config().base_url)
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
