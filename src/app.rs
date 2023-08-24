use std::{net::SocketAddr, path::Path, sync::Arc};

use crate::store::UserStore;
use serde::{Deserialize, Serialize};
use sqlx::sqlite::SqlitePoolOptions;
use tokio::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

#[derive(Clone)]
pub struct AppState(Arc<RwLock<AppStateInner>>);

pub struct AppStateInner {
    pub config: AppConfig,
    pub store: UserStore,
}

impl AppState {
    pub async fn from_config(config: AppConfig) -> anyhow::Result<Self> {
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect(config.users_db.as_str())
            .await?;

        let store = UserStore::new(pool);

        let state = AppStateInner { config, store };

        Ok(AppState(Arc::new(RwLock::new(state))))
    }

    pub async fn read(&self) -> RwLockReadGuard<AppStateInner> {
        self.0.read().await
    }

    pub async fn write(&self) -> RwLockWriteGuard<AppStateInner> {
        self.0.write().await
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
