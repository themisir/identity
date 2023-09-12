use crate::app::AppState;
use crate::http::{get_header, AppError, Cookies, Either, SetCookie};
use crate::proxy::{UpstreamAuthorizeParams, PROXY_AUTHORIZE_ENDPOINT, PROXY_TOKEN_TTL};
use crate::store::User;
use crate::uri::UriBuilder;

use std::borrow::Cow;

use axum::{
    async_trait,
    extract::{FromRequestParts, Query, State},
    http::{header::AUTHORIZATION, request::Parts, StatusCode},
    response::{Html, IntoResponse, Redirect},
    Form,
};
use chrono::Duration;
use cookie::{Cookie, SameSite};
use log::error;
use serde::{Deserialize, Serialize};

pub const CORE_ISSUER: &str = "core";

const COOKIE_NAME: &str = "_im";

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
    match auth.user() {
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

pub async fn show_login(
    Query(params): Query<RedirectParams>,
    auth: Authorize,
) -> Result<Either<Html<&'static str>, Redirect>, AppError> {
    if auth.user().is_some() {
        let redirect_to = params.redirect_to.unwrap_or("/".to_string());

        Ok(Either::Second(Redirect::to(redirect_to.as_str())))
    } else {
        Ok(Either::First(Html(include_str!("templates/login.html"))))
    }
}

#[axum_macros::debug_handler]
pub async fn show_unauthorized() -> impl IntoResponse {
    Html(include_str!("templates/unauthorized.html"))
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
                Authorize::set_cookie(session_token, Some(Duration::days(30))),
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

pub struct Authorize {
    user: Option<User>,
}

impl Authorize {
    pub(crate) async fn from_token(token: &str, state: &AppState) -> anyhow::Result<Self> {
        let user = state
            .store()
            .find_user_by_session(token, Some(CORE_ISSUER))
            .await?;

        Ok(Self { user })
    }

    pub fn user(&self) -> Option<&User> {
        self.user.as_ref()
    }

    pub fn set_cookie<'c, V>(token: V, ttl: Option<Duration>) -> SetCookie<'c>
    where
        V: Into<Cow<'c, str>>,
    {
        let ttl = ttl.unwrap_or(Duration::days(30));
        let cookie = Cookie::build(COOKIE_NAME, token)
            .max_age(cookie::time::Duration::new(ttl.num_seconds(), 0))
            .path("/")
            .http_only(true)
            .same_site(SameSite::Strict)
            .finish();

        SetCookie(cookie)
    }

    pub fn clear_cookie<'c>() -> SetCookie<'c> {
        Self::set_cookie("", Some(Duration::seconds(1))) // short ttl, removes cookie
    }
}

#[derive(Serialize, Deserialize)]
pub struct TokenParams {
    pub token: String,
}

#[async_trait]
impl FromRequestParts<AppState> for Authorize {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // extract from header
        if let Some(auth_header) = get_header(&parts.headers, AUTHORIZATION) {
            if auth_header.len() > 7 && auth_header.starts_with("Bearer ") {
                return Ok(Self::from_token(&auth_header[7..], state).await?);
            }
        }

        // extract from query
        if let Ok(Query(TokenParams { token })) = Query::try_from_uri(&parts.uri) {
            return Ok(Self::from_token(token.as_ref(), state).await?);
        };

        // extract from cookie
        if let Some(cookie) = Cookies::extract_one(&parts.headers, COOKIE_NAME) {
            return Ok(Self::from_token(cookie.value(), state).await?);
        }

        Ok(Self { user: None })
    }
}
