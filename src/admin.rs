use crate::app::AppState;
use crate::auth::{Authorize, RedirectParams, TokenParams, CORE_ISSUER};
use crate::http::AppError;
use crate::store::{User, UserClaim, UserRole};

use crate::uri::UriBuilder;
use askama::Template;
use axum::extract::OriginalUri;
use axum::{
    extract::{Form, Path, State},
    http::{Request, StatusCode},
    middleware,
    middleware::Next,
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Router,
};
use chrono::Duration;
use hyper::Body;
use serde::Deserialize;

pub fn create_router(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/users", get(get_users_page))
        .route("/users/add", get(add_user_page))
        .route("/users/add", post(add_user_handler))
        .route("/users/:user_id/update", post(update_user_handler))
        .route("/users/:user_id/claims", get(get_user_claims_page))
        .route(
            "/users/:user_id/create-pw-session",
            get(create_user_pw_session_handler),
        )
        .route(
            "/users/:user_id/claims/delete",
            post(delete_user_claim_handler),
        )
        .route("/users/:user_id/claims/add", post(add_user_claim_handler))
        .layer(middleware::from_fn_with_state(state, authorize_admin))
}

pub fn create_setup_router(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/", get(add_first_user_page))
        .route("/", post(add_first_user_handler))
        .layer(middleware::from_fn_with_state(state, authorize_setup))
}

pub fn create_password_change_router(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/", get(change_password_page))
        .route("/", post(change_password_handler))
        .layer(middleware::from_fn_with_state(state, authorize_user))
}

async fn authorize_setup(
    State(state): State<AppState>,
    request: Request<Body>,
    next: Next<Body>,
) -> Result<Response, AppError> {
    Ok(if state.store().has_any_user().await? {
        StatusCode::FORBIDDEN.into_response()
    } else {
        next.run(request).await
    })
}

async fn authorize_admin(
    auth: Authorize,
    OriginalUri(uri): OriginalUri,
    request: Request<Body>,
    next: Next<Body>,
) -> Result<Response, AppError> {
    if let Some(User { role, .. }) = auth.user() {
        if *role == UserRole::Admin {
            return Ok(next.run(request).await);
        }
    }

    let redirect_to = UriBuilder::new()
        .set_path("/login")
        .append_params(RedirectParams {
            redirect_to: Some(uri.to_string()),
        })
        .to_string();

    Ok(Redirect::to(redirect_to.as_str()).into_response())
}

async fn authorize_user(
    auth: Authorize,
    request: Request<Body>,
    next: Next<Body>,
) -> Result<Response, AppError> {
    Ok(match auth.user() {
        None => StatusCode::UNAUTHORIZED.into_response(),
        Some(_) => next.run(request).await,
    })
}

#[axum_macros::debug_handler]
async fn create_user_pw_session_handler(
    State(state): State<AppState>,
    Path(user_id): Path<i32>,
) -> Result<Redirect, AppError> {
    let token = state
        .store()
        .create_user_session(user_id, CORE_ISSUER, Some(Duration::minutes(30)))
        .await?;

    let url = UriBuilder::new()
        .set_path("/change-password")
        .append_params(TokenParams { token })
        .to_string();

    Ok(Redirect::to(url.as_str()))
}

#[derive(Template)]
#[template(path = "password.html")]
struct ChangePasswordTemplate<'a> {
    username: &'a str,
}

async fn change_password_page(authorize: Authorize) -> Result<impl IntoResponse, AppError> {
    let user = authorize
        .user()
        .ok_or(anyhow::format_err!("unauthorized"))?;

    let body = ChangePasswordTemplate {
        username: user.username.as_str(),
    }
    .render()?;

    Ok(Html(body))
}

#[derive(Deserialize)]
struct ChangePasswordDto {
    password: String,
}

#[axum_macros::debug_handler]
async fn change_password_handler(
    State(state): State<AppState>,
    authorize: Authorize,
    Form(form): Form<ChangePasswordDto>,
) -> Result<impl IntoResponse, AppError> {
    let user = authorize
        .user()
        .ok_or(anyhow::format_err!("unauthorized"))?;

    state
        .store()
        .change_user_password(user.id, form.password.as_str())
        .await?;

    Ok(Html("Password updated!"))
}

#[derive(Template)]
#[template(path = "users.html")]
struct UsersTemplate<'a> {
    users: &'a [User],
}

#[axum_macros::debug_handler]
async fn get_users_page(State(state): State<AppState>) -> Result<impl IntoResponse, AppError> {
    let users = state.store().get_all_users().await?;
    let body = UsersTemplate { users: &users }.render()?;

    Ok(Html(body))
}

#[derive(Template)]
#[template(path = "add-user.html")]
struct AddUserTemplate {
    role: Option<UserRole>,
}

#[axum_macros::debug_handler]
async fn add_first_user_page() -> Result<impl IntoResponse, AppError> {
    let body = AddUserTemplate {
        role: Some(UserRole::Admin),
    }
    .render()?;

    Ok(Html(body))
}

#[axum_macros::debug_handler]
async fn add_user_page() -> Result<impl IntoResponse, AppError> {
    let body = AddUserTemplate { role: None }.render()?;

    Ok(Html(body))
}

#[derive(Deserialize)]
struct AddUserDto {
    username: String,
    password: String,
    role: UserRole,
}

#[axum_macros::debug_handler]
async fn add_user_handler(
    State(state): State<AppState>,
    Form(form): Form<AddUserDto>,
) -> Result<impl IntoResponse, AppError> {
    state
        .store()
        .create_user(&form.username, &form.password, form.role)
        .await?;

    // TODO: generate a password change session

    Ok(Redirect::to("/admin/users"))
}

#[axum_macros::debug_handler]
async fn add_first_user_handler(
    State(state): State<AppState>,
    Form(form): Form<AddUserDto>,
) -> Result<impl IntoResponse, AppError> {
    let user = state
        .store()
        .create_user(&form.username, &form.password, UserRole::Admin)
        .await?;

    let ttl = Some(Duration::days(15));
    let session_token = state
        .store()
        .create_user_session(user.id, CORE_ISSUER, ttl)
        .await?;

    Ok((
        Authorize::set_cookie(session_token, ttl),
        Redirect::to("/admin/users"),
    ))
}

#[derive(Deserialize)]
struct UpdateUserDto {
    role: UserRole,
}

#[axum_macros::debug_handler]
async fn update_user_handler(
    State(state): State<AppState>,
    Path(user_id): Path<i32>,
    Form(form): Form<UpdateUserDto>,
) -> Result<impl IntoResponse, AppError> {
    let modified = state.store().update_user_role(user_id, form.role).await?;

    let redirect_url = format!("/admin/users?id={}&modified={}", user_id, modified);

    Ok(Redirect::to(redirect_url.as_str()))
}

#[derive(Template)]
#[template(path = "claims.html")]
struct UserClaimsTemplate<'a> {
    claims: &'a [UserClaim],
    user_id: i32,
}

#[axum_macros::debug_handler]
async fn get_user_claims_page(
    State(state): State<AppState>,
    Path(user_id): Path<i32>,
) -> Result<impl IntoResponse, AppError> {
    let claims = state.store().get_user_claims(user_id).await?;
    let body = UserClaimsTemplate {
        claims: &claims,
        user_id,
    }
    .render()?;

    Ok(Html(body))
}

#[derive(Deserialize)]
struct DeleteUserClaimDto {
    claim_name: String,
}

#[axum_macros::debug_handler]
async fn delete_user_claim_handler(
    State(state): State<AppState>,
    Path(user_id): Path<i32>,
    Form(form): Form<DeleteUserClaimDto>,
) -> Result<impl IntoResponse, AppError> {
    let modified = state
        .store()
        .delete_user_claim_by_name(user_id, &form.claim_name)
        .await?;

    let redirect_url = format!("/admin/users/{}/claims?modified={}", user_id, modified);

    Ok(Redirect::to(redirect_url.as_str()))
}

#[derive(Deserialize)]
struct AddUserClaimDto {
    claim_name: String,
    claim_value: String,
}

#[axum_macros::debug_handler]
async fn add_user_claim_handler(
    State(state): State<AppState>,
    Path(user_id): Path<i32>,
    Form(form): Form<AddUserClaimDto>,
) -> Result<impl IntoResponse, AppError> {
    let modified = state
        .store()
        .add_user_claim(
            user_id,
            UserClaim {
                name: form.claim_name,
                value: form.claim_value,
            },
        )
        .await?;

    let redirect_url = format!("/admin/users/{}/claims?modified={}", user_id, modified);

    Ok(Redirect::to(redirect_url.as_str()))
}
