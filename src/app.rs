use std::{net::SocketAddr, path::Path};

use serde::{Deserialize, Serialize};
use sqlx::sqlite::SqlitePoolOptions;
use crate::store::UserStore;

#[derive(Clone)]
pub struct AppState {
    pub config: Box<AppConfig>,
    pub store: UserStore,
}

impl AppState {
    pub async fn from_config(config: AppConfig) -> anyhow::Result<Self> {
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect(config.users_db.as_str()).await?;

        let store = UserStore::new(pool);

        Ok(AppState {
            config: Box::new(config),
            store,
        })
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AppConfig {
    pub bind: SocketAddr,
    pub base_url: String,
    pub users_db: String,
    pub upstreams: Vec<UpstreamConfig>,
}

impl AppConfig {
    pub async fn from_file(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let contents = tokio::fs::read_to_string(&path).await?;
        Ok(serde_json::from_str(contents.as_str())?)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UpstreamConfig {
    pub name: String,
    pub target_url: String,
    pub claims: Vec<String>,

    // authorization rules
    pub require_claims: Option<Vec<String>>,
    pub require_authentication: bool,
}
