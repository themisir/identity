use crate::app::AppState;
use crate::http::{Cookies, SetCookie, UriQueryBuilder};
use crate::proxy::{ProxyClient, PROXY_AUTHORIZE_ENDPOINT, PROXY_TOKEN_TTL};
use crate::store::{User, UserStore};
use async_trait::async_trait;
use axum::body::BoxBody;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::Response;
use axum::{
    extract::{Query, State},
    http::{
        header::{AsHeaderName, AUTHORIZATION},
        Request, StatusCode,
    },
    response::{Html, IntoResponse, Redirect},
    Form,
};
use chrono::Duration;
use cookie::{Cookie, SameSite};
use hyper::{Body, HeaderMap};
use log::error;
use serde::Deserialize;
use std::convert::Infallible;

const COOKIE_NAME: &str = "_im";
const CORE_ISSUER: &str = "core";

#[derive(Deserialize, Debug)]
pub struct LoginRequestBody {
    username: String,
    password: String,
}

#[derive(Deserialize, Debug)]
pub struct RedirectParams {
    client_id: Option<String>,
    redirect_to: Option<String>,
}

#[axum_macros::debug_handler]
pub async fn logout(Query(redirect): Query<RedirectParams>) -> impl IntoResponse {
    let redirect_to = redirect.redirect_to.unwrap_or("/".to_string());

    (
        AuthParams::clear_cookie(),
        Redirect::to(redirect_to.as_str()),
    )
}

#[axum_macros::debug_handler]
pub async fn show_login(
    State(state): State<AppState>,
    Query(redirect): Query<RedirectParams>,
    auth: AuthParams,
) -> Result<Response<BoxBody>, StatusCode> {
    let state = state.read().await;
    let user = auth.find_user(&state.store).await.map_err(|err| {
        error!("failed to find user: {}", err);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let response = match (user, redirect.redirect_to, redirect.client_id) {
        (Some(user), Some(redirect_to), Some(client_id)) => {
            match state.upstreams.find_by_name(client_id.as_str()) {
                None => StatusCode::BAD_REQUEST.into_response(),
                Some(upstream) => {
                    let claims = state.store.get_user_claims(user.id).await.map_err(|err| {
                        error!("failed to get user {} claims: {}", user.id, err);
                        StatusCode::INTERNAL_SERVER_ERROR
                    })?;

                    // todo: filter claims for client

                    let token = state
                        .issuer
                        .create_token(upstream.name(), &user, claims.as_ref(), (*PROXY_TOKEN_TTL).into())
                        .map_err(|err| {
                            error!("failed to create token: {}", err);
                            StatusCode::INTERNAL_SERVER_ERROR
                        })?;

                    let path_and_query = UriQueryBuilder::new(PROXY_AUTHORIZE_ENDPOINT)
                        .append("redirect_to", redirect_to)
                        .append("token", token)
                        .build()
                        .try_into()
                        .map_err(|err| {
                            error!("failed to build uri: {}", err);
                            StatusCode::INTERNAL_SERVER_ERROR
                        })?;

                    let redirect_to_uri = upstream.upstream_uri(Some(path_and_query)).map_err(|err| {
                        error!("failed to create uri: {}", err);
                        StatusCode::INTERNAL_SERVER_ERROR
                    })?;

                    Redirect::to(redirect_to_uri.to_string().as_str()).into_response()
                }
            }
        }
        (Some(_), Some(redirect_to), None) => Redirect::to(redirect_to.as_str()).into_response(),
        (Some(_), None, _) => Redirect::to("/").into_response(),
        _ => Html(include_str!("ui/login.html")).into_response(),
    };

    Ok(response)
}

#[axum_macros::debug_handler]
pub async fn handle_login(
    State(state): State<AppState>,
    Query(redirect): Query<RedirectParams>,
    Form(body): Form<LoginRequestBody>,
) -> Result<impl IntoResponse, StatusCode> {
    let state = state.read().await;

    let user = state
        .store
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
                .store
                .create_user_session(user.id, CORE_ISSUER, ttl)
                .await
                .map_err(|err| {
                    error!(
                        "unable to create session for user '{}': {}",
                        user.username, err
                    );
                    StatusCode::INTERNAL_SERVER_ERROR
                })?;

            let redirect_to = redirect.redirect_to.unwrap_or("/".to_string());

            return Ok((
                AuthParams::new(session_token).set_cookie(Some(Duration::days(30))),
                Redirect::to(redirect_to.as_str()),
            ));
        }
    }

    let mut login_uri = UriQueryBuilder::new(format!("{}/login?", state.config.base_url));
    if let Some(redirect_to) = redirect.redirect_to {
        login_uri = login_uri.append("redirect_to", redirect_to);
    }

    Ok((
        AuthParams::clear_cookie(),
        Redirect::to(
            login_uri
                .append("error", "invalid_password")
                .build()
                .as_str(),
        ),
    ))
}

#[derive(Default, Clone)]
pub struct AuthParams {
    pub session_token: Option<String>,
}

impl AuthParams {
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
        AuthParams::default().set_cookie(Some(Duration::seconds(1))) // short ttl, removes cookie
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
impl FromRequestParts<AppState> for AuthParams {
    type Rejection = Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let params = Cookies::from_headers(&parts.headers)
            .get(COOKIE_NAME)
            .map(|cookie| AuthParams::new(cookie.value().into()))
            .or_else(|| {
                get_header(&parts.headers, AUTHORIZATION).and_then(|auth_header| {
                    if auth_header.len() > 7 && auth_header.starts_with("Bearer ") {
                        Some(AuthParams::new(auth_header[7..].into()))
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
