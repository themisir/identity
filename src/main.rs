#![feature(iter_collect_into)]

use std::net::SocketAddr;

use app::{AppConfig, AppState};
use axum::{
    extract::State,
    middleware,
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Router,
};
use clap::{Args, Parser, Subcommand};
use log::info;
use tokio::signal;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod admin;
mod app;
mod auth;
mod http;
mod issuer;
mod proxy;
mod store;
mod uri;
mod utils;

mod keystore;

/// Identity and user management proxy
#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
struct AppArgs {
    #[command(subcommand)]
    command: Commands,

    /// Config file path
    #[arg(short, long, default_value = "./config.json")]
    config_file: String,

    /// Disable automatic migration
    #[arg(short, long, default_value = "false")]
    no_migration: bool,
}

#[derive(Subcommand, Debug, Clone)]
enum Commands {
    /// Start server
    Listen(ListenArgs),

    /// Add a new user
    AddUser(AddUserArgs),
}

#[derive(Args, Debug, Clone)]
struct ListenArgs {
    /// Bind address
    #[arg(long, default_value = "0.0.0.0:3000")]
    pub bind: SocketAddr,
}

#[derive(Args, Debug, Clone)]
struct AddUserArgs {
    #[arg(long)]
    pub username: String,

    #[arg(long)]
    pub password: String,

    #[arg(long, default_value = "user")]
    pub role: store::UserRole,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "identity=trace,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let app_args = AppArgs::parse();

    let app_config = AppConfig::from_file(app_args.config_file).await?;

    if !app_args.no_migration {
        store::migrate(&app_config).await?;
    }

    let app_state = AppState::from_config(app_config).await?;

    match app_args.command {
        Commands::Listen(args) => start_server(app_state, &args).await,
        Commands::AddUser(args) => add_user(app_state, &args).await,
    }
}

async fn start_server(state: AppState, args: &ListenArgs) -> anyhow::Result<()> {
    let router = Router::new()
        .route("/", get(index_handler))
        .route("/login", get(auth::show_login))
        .route("/login", post(auth::handle_login))
        .route("/logout", get(auth::logout))
        .route("/authorize", get(auth::authorize))
        .route("/unauthorized", get(auth::show_unauthorized))
        .route(
            "/.well-known/openid-configuration",
            get(issuer::discovery_handler),
        )
        .route("/.well-known/jwks", get(issuer::jwk_handler))
        .nest("/admin", admin::create_router(state.clone()))
        .nest("/setup", admin::create_setup_router(state.clone()))
        .nest(
            "/change-password",
            admin::create_password_change_router(state.clone()),
        )
        .layer(middleware::from_fn_with_state(
            state.clone(),
            proxy::middleware,
        ))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    info!("Binding on {}", args.bind);

    axum::Server::bind(&args.bind)
        .serve(router.into_make_service())
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

#[axum_macros::debug_handler]
async fn index_handler(State(state): State<AppState>) -> Result<Response, http::AppError> {
    if state.store().has_any_user().await? {
        Ok(Html(include_str!("templates/home.html")).into_response())
    } else {
        Ok(Redirect::to("/setup").into_response())
    }
}

async fn add_user(app_state: AppState, args: &AddUserArgs) -> anyhow::Result<()> {
    let user = app_state
        .store()
        .create_user(args.username.as_str(), args.password.as_str(), args.role)
        .await?;

    print!("User created: {:?}", user);

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    info!("Signal received, starting graceful shutdown");
}
