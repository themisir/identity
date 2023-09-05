use crate::app::AppState;
use crate::http::AppError;
use crate::store::{User, UserClaim, UserRole};

use askama::Template;
use axum::{
    extract::{Form, Path, State},
    response::{Html, IntoResponse, Redirect},
    routing::{get, post},
    Router,
};
use serde::Deserialize;

pub fn create_router() -> Router<AppState> {
    Router::new()
        .route("/users", get(get_users_page))
        .route("/users/add", get(add_user_add_page))
        .route("/users/add", post(add_user_handler))
        .route("/users/:user_id/update", post(update_user_handler))
        .route("/users/:user_id/claims", get(get_user_claims_page))
        .route(
            "/users/:user_id/claims/delete",
            post(delete_user_claim_handler),
        )
        .route("/users/:user_id/claims/add", post(add_user_claim_handler))
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
struct AddUserTemplate {}

#[axum_macros::debug_handler]
async fn add_user_add_page() -> Result<impl IntoResponse, AppError> {
    let body = AddUserTemplate {}.render()?;

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
