use crate::app::AppState;
use crate::http::{Cookies, SetCookie};
use crate::proxy::{UpstreamAuthorizeParams, PROXY_AUTHORIZE_ENDPOINT, PROXY_TOKEN_TTL};
use crate::store::{User, UserStore};
use crate::uri::UriBuilder;

use std::convert::Infallible;

use axum::{
    async_trait,
    extract::{FromRequestParts, Query, State},
    http::{
        header::{AsHeaderName, AUTHORIZATION},
        request::Parts,
        HeaderMap, StatusCode,
    },
    response::{Html, IntoResponse, Redirect},
    Form,
};
use chrono::Duration;
use cookie::{Cookie, SameSite};
use log::error;
use serde::{Deserialize, Serialize};

const COOKIE_NAME: &str = "_im";
const CORE_ISSUER: &str = "core";

#[derive(Deserialize, Debug)]
pub struct LoginRequestBody {
    username: String,
    password: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RedirectParams {
    redirect_to: Option<String>,
}

#[axum_macros::debug_handler]
pub async fn logout(Query(redirect): Query<RedirectParams>) -> impl IntoResponse {
    let redirect_to = redirect.redirect_to.unwrap_or("/".to_string());

    (
        Authorize::clear_cookie(),
        Redirect::to(redirect_to.as_str()),
    )
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AuthorizeParams {
    pub client_id: String,
    pub redirect_to: String,
}

#[axum_macros::debug_handler]
pub async fn authorize(
    State(state): State<AppState>,
    Query(params): Query<AuthorizeParams>,
    auth: Authorize,
) -> Result<Redirect, StatusCode> {
    let user = auth.find_user(state.store()).await.unwrap_or_else(|err| {
        error!("failed to find user: {}", err);
        None
    });

    match user {
        None => {
            let authorize_uri = UriBuilder::new()
                .append_path("/authorize")
                .append_params(params)
                .to_string();

            let redirect_uri = UriBuilder::new()
                .append_path("/login")
                .append_params(RedirectParams {
                    redirect_to: Some(authorize_uri),
                })
                .to_string();

            Ok(Redirect::to(redirect_uri.as_str()))
        }
        Some(user) => match state.upstreams().find_by_name(params.client_id.as_str()) {
            None => Err(StatusCode::BAD_REQUEST),
            Some(upstream) => {
                let claims = state
                    .store()
                    .get_user_claims(user.id)
                    .await
                    .map_err(|err| {
                        error!("failed to get user {} claims: {}", user.id, err);
                        StatusCode::INTERNAL_SERVER_ERROR
                    })?;

                if let Some(claims) = upstream.filter_claims(claims) {
                    let token = state
                        .issuer()
                        .create_token(
                            upstream.name(),
                            &user,
                            claims.as_ref(),
                            (*PROXY_TOKEN_TTL).into(),
                        )
                        .map_err(|err| {
                            error!("failed to create token: {}", err);
                            StatusCode::INTERNAL_SERVER_ERROR
                        })?;

                    let upstream_authorize_uri = UriBuilder::new()
                        .set_origin(upstream.origin())
                        .set_path(PROXY_AUTHORIZE_ENDPOINT)
                        .append_params(UpstreamAuthorizeParams {
                            token,
                            redirect_to: params.redirect_to,
                        })
                        .to_string();

                    Ok(Redirect::to(upstream_authorize_uri.as_str()))
                } else {
                    Ok(Redirect::to(
                        UriBuilder::new()
                            .set_path("/unauthorized")
                            .append_param("client_id", params.client_id)
                            .to_string()
                            .as_str(),
                    ))
                }
            }
        },
    }
}

#[axum_macros::debug_handler]
pub async fn show_login() -> impl IntoResponse {
    Html(include_str!("ui/login.html"))
}

#[axum_macros::debug_handler]
pub async fn show_unauthorized() -> impl IntoResponse {
    Html(include_str!("ui/unauthorized.html"))
}

#[axum_macros::debug_handler]
pub async fn handle_login(
    State(state): State<AppState>,
    Query(params): Query<RedirectParams>,
    Form(body): Form<LoginRequestBody>,
) -> Result<impl IntoResponse, StatusCode> {
    let user = state
        .store()
        .find_user_by_username(body.username.as_str())
        .await
        .map_err(|err| {
            error!(
                "unable to find user by username '{}': {}",
                body.username, err
            );
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    if let Some(user) = user {
        if user.check_password(body.password.as_bytes()) {
            // authorize!
            // already on it do not you worry!

            let ttl = Some(Duration::days(30));
            let session_token = state
                .store()
                .create_user_session(user.id, CORE_ISSUER, ttl)
                .await
                .map_err(|err| {
                    error!(
                        "unable to create session for user '{}': {}",
                        user.username, err
                    );
                    StatusCode::INTERNAL_SERVER_ERROR
                })?;

            let redirect_to = params.redirect_to.unwrap_or("/".to_string());

            return Ok((
                Authorize::new(session_token).set_cookie(Some(Duration::days(30))),
                Redirect::to(redirect_to.as_str()),
            ));
        }
    }

    let mut login_uri = UriBuilder::from_url(&state.config().base_url)
        .set_path("/login")
        .append_param("error", "invalid_password");

    if let Some(redirect_to) = params.redirect_to {
        login_uri = login_uri.append_param("redirect_to", redirect_to);
    }

    Ok((
        Authorize::clear_cookie(),
        Redirect::to(login_uri.to_string().as_str()),
    ))
}

#[derive(Default, Clone)]
pub struct Authorize {
    pub session_token: Option<String>,
}

impl Authorize {
    pub fn new(session_token: String) -> Self {
        Self {
            session_token: Some(session_token),
        }
    }

    pub fn set_cookie<'c>(self, ttl: Option<Duration>) -> SetCookie<'c> {
        let ttl = ttl.unwrap_or(Duration::days(30));
        let cookie_value = match self.session_token {
            None => String::default(),
            Some(s) => s,
        };
        let cookie = Cookie::build(COOKIE_NAME, cookie_value)
            .max_age(cookie::time::Duration::new(ttl.num_seconds(), 0))
            .path("/")
            .http_only(true)
            .same_site(SameSite::Strict)
            .finish();

        SetCookie(cookie)
    }

    pub fn clear_cookie<'c>() -> SetCookie<'c> {
        Authorize::default().set_cookie(Some(Duration::seconds(1))) // short ttl, removes cookie
    }

    pub async fn find_user(&self, store: &UserStore) -> anyhow::Result<Option<User>> {
        if let Some(token) = &self.session_token {
            store
                .find_user_by_session(token.as_str(), Some(CORE_ISSUER))
                .await
        } else {
            Ok(None)
        }
    }
}

#[async_trait]
impl FromRequestParts<AppState> for Authorize {
    type Rejection = Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let params = Cookies::from_headers(&parts.headers)
            .get(COOKIE_NAME)
            .map(|cookie| Authorize::new(cookie.value().into()))
            .or_else(|| {
                get_header(&parts.headers, AUTHORIZATION).and_then(|auth_header| {
                    if auth_header.len() > 7 && auth_header.starts_with("Bearer ") {
                        Some(Authorize::new(auth_header[7..].into()))
                    } else {
                        None
                    }
                })
            })
            .unwrap_or(Self {
                session_token: None,
            });

        Ok(params)
    }
}

fn get_header<K>(headers: &HeaderMap, key: K) -> Option<&str>
where
    K: AsHeaderName,
{
    headers.get(key).and_then(|header| header.to_str().ok())
}
