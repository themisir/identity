#![feature(file_create_new)]
#![feature(iter_collect_into)]

use app::{AppConfig, AppState};
use axum::{
    middleware,
    routing::{get, post},
    Router,
};
use clap::{Args, Parser, Subcommand};
use log::info;
use tokio::signal;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod app;
mod auth;
mod http;
mod issuer;
mod proxy;
mod store;
mod uri;
mod utils;

/// Identity and user management proxy
#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
pub struct AppArgs {
    #[command(subcommand)]
    pub command: Commands,

    /// Config file path
    #[arg(short, long, default_value = "./config.json")]
    pub config_file: String,

    /// Disable automatic migration
    #[arg(short, long, default_value = "false")]
    pub no_migration: bool,
}

#[derive(Subcommand, Debug, Clone)]
pub enum Commands {
    /// Start server
    Listen,

    /// Add a new user
    AddUser(AddUserArgs),
}

#[derive(Args, Debug, Clone)]
pub struct AddUserArgs {
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

    let app_state = AppState::from_config(app_config.clone()).await?;

    match app_args.command {
        Commands::Listen => start_server(app_state, &app_config).await,
        Commands::AddUser(args) => add_user(app_state, &args).await,
    }
}

async fn start_server(app_state: AppState, app_config: &AppConfig) -> anyhow::Result<()> {
    let routes = Router::new()
        .route("/login", get(auth::show_login))
        .route("/login", post(auth::handle_login))
        .route("/logout", post(auth::logout))
        .route("/authorize", get(auth::authorize))
        .route(
            "/.well-known/openid-configuration",
            get(issuer::discovery_handler),
        )
        .route("/.well-known/jwks", get(issuer::jwk_handler))
        .layer(middleware::from_fn_with_state(
            app_state.clone(),
            proxy::middleware,
        ))
        .layer(TraceLayer::new_for_http())
        .with_state(app_state);

    info!("Binding on {}", app_config.bind);

    axum::Server::bind(&app_config.bind)
        .serve(routes.into_make_service())
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
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
