use crate::app::AppState;
use axum::{
    extract::{Query, State},
    http::{
        header::{AsHeaderName, AUTHORIZATION, COOKIE, SET_COOKIE},
        HeaderValue, Request, StatusCode,
    },
    response::{Html, IntoResponse, IntoResponseParts, Redirect, ResponseParts},
    Form,
};
use chrono::Duration;
use cookie::{Cookie, SameSite};
use log::error;
use serde::Deserialize;
use url::form_urlencoded;

const AUTH_COOKIE_NAME: &str = "_im";
const CORE_ISSUER: &str = "core";

#[derive(Deserialize, Debug)]
pub struct LoginRequestBody {
    username: String,
    password: String,
}

#[derive(Deserialize, Debug)]
pub struct RedirectParams {
    redirect_to: Option<String>,
}

#[axum_macros::debug_handler]
pub async fn logout(Query(redirect): Query<RedirectParams>) -> impl IntoResponse {
    let redirect_to = redirect.redirect_to.unwrap_or("/".to_string());

    (
        AuthParams::clear_cookie(),
        Redirect::temporary(redirect_to.as_str()),
    )
}

#[axum_macros::debug_handler]
pub async fn show_login() -> impl IntoResponse {
    Html(include_str!("ui/login.html"))
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
                Redirect::temporary(redirect_to.as_str()),
            ));
        }
    }

    Ok((
        AuthParams::clear_cookie(),
        redirect_with_params("/login?error=invalid_password&", move |builder| {
            if let Some(redirect_to) = redirect.redirect_to {
                builder.append_pair("redirect_to", redirect_to.as_str());
            }
        }),
    ))
}

fn redirect_with_params<B: FnOnce(&mut form_urlencoded::Serializer<String>)>(
    prefix: &str,
    builder: B,
) -> Redirect {
    let mut serializer = form_urlencoded::Serializer::new(String::from(prefix));
    {
        builder(&mut serializer);
    }
    Redirect::temporary(serializer.finish().as_str())
}

#[derive(Default, Clone)]
struct AuthParams {
    pub session_token: Option<String>,
}

impl AuthParams {
    pub fn new(session_token: String) -> Self {
        Self {
            session_token: Some(session_token),
        }
    }

    pub fn from_cookie(cookie_header: &str) -> Option<Self> {
        Cookie::split_parse(cookie_header)
            .filter_map(|cookie| cookie.ok())
            .find(|cookie| cookie.name() == AUTH_COOKIE_NAME)
            .map(|cookie| AuthParams {
                session_token: Some(cookie.value().into()),
            })
    }

    pub fn from_header(auth_header: &str) -> Option<Self> {
        if auth_header.len() > 7 && auth_header.starts_with("Bearer ") {
            Some(AuthParams {
                session_token: Some(auth_header[7..].into()),
            })
        } else {
            None
        }
    }

    pub fn from_request<B>(req: &Request<B>) -> Self
    where
        B: Send + 'static,
    {
        get_header(req, COOKIE)
            .and_then(Self::from_cookie)
            .or_else(|| get_header(req, AUTHORIZATION).and_then(Self::from_header))
            .unwrap_or(AuthParams {
                session_token: None,
            })
    }

    pub fn set_cookie<'c>(&self, ttl: Option<Duration>) -> SetCookie<'c> {
        let ttl = ttl.unwrap_or(Duration::days(30));
        let cookie_value = self.session_token.clone().unwrap_or("".into());
        let cookie = Cookie::build(AUTH_COOKIE_NAME, cookie_value)
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
}

pub struct SetCookie<'c>(Cookie<'c>);

impl<'c> IntoResponseParts for SetCookie<'c> {
    type Error = StatusCode;

    fn into_response_parts(self, mut res: ResponseParts) -> Result<ResponseParts, Self::Error> {
        let value = HeaderValue::from_str(self.0.encoded().to_string().as_str())
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        res.headers_mut().append(SET_COOKIE, value);
        Ok(res)
    }
}

fn get_header<B, K>(req: &Request<B>, key: K) -> Option<&str>
where
    B: Send + 'static,
    K: AsHeaderName,
{
    req.headers()
        .get(key)
        .and_then(|header| header.to_str().ok())
}
