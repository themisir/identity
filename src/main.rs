use anyhow::anyhow;
use app::{AppConfig, AppState};
use axum::Router;
use tokio::signal;

mod app;
mod store;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let app_config = AppConfig::from_file("./config.json").await?;

    store::migrate(&app_config).await?;

    let app_state = AppState::from_config(app_config.clone()).await?;

    let routes = Router::new()
        .with_state(app_state);

    axum::Server::bind(&app_config.bind)
        .serve(routes.into_make_service())
        .with_graceful_shutdown(shutdown_signal())
        .await?;

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

    println!("signal received, starting graceful shutdown");
}
