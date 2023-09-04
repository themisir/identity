use anyhow::anyhow;
use std::{collections::HashMap, net::SocketAddr, path::Path, sync::Arc};

use crate::issuer::Issuer;
use crate::proxy::ProxyClient;
use crate::store::UserStore;
use serde::{Deserialize, Serialize};
use sqlx::sqlite::SqlitePoolOptions;
use tokio::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

#[derive(Clone)]
pub struct AppState(Arc<RwLock<AppStateInner>>);

pub struct AppStateInner {
    pub config: AppConfig,
    pub store: UserStore,
    pub upstreams: Upstreams,
    pub issuer: Issuer,
}

impl AppState {
    pub async fn from_config(config: AppConfig) -> anyhow::Result<Self> {
        // create db pool and store
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect(config.users_db.as_str())
            .await?;
        let store = UserStore::new(pool);

        // token issuer
        let issuer = Issuer::new(config.base_url.as_str());

        // upstream clients
        let upstreams = Upstreams::from_config(config.upstreams.as_ref())?;

        Ok(AppState(Arc::new(RwLock::new(AppStateInner {
            config: config.clone(),
            store,
            upstreams,
            issuer,
        }))))
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
        let mut config: AppConfig = serde_json::from_str(contents.as_str())?;

        // remove trailing slash
        config.base_url = config.base_url.trim_end_matches('/').into();

        Ok(config)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UpstreamConfig {
    pub name: String,
    pub hostname: String,
    pub target_url: String,
    pub claims: Vec<String>,

    // authorization rules
    pub require_claims: Option<Vec<String>>,
    pub require_authentication: bool,
}

pub struct Upstreams {
    by_name: HashMap<String, Arc<ProxyClient>>,
    by_host: HashMap<String, Arc<ProxyClient>>,
}

impl Upstreams {
    pub fn from_config(upstreams: &[UpstreamConfig]) -> anyhow::Result<Self> {
        let mut by_name = HashMap::new();
        let mut by_host = HashMap::new();

        for cfg in upstreams {
            let client: Arc<ProxyClient> = ProxyClient::new(cfg)?.into();

            if by_name.insert(cfg.name.clone(), client.clone()).is_some() {
                return Err(anyhow!(
                    "upstream with the name {} declared more than once",
                    cfg.name
                ));
            }
            if by_host.insert(cfg.hostname.clone(), client).is_some() {
                return Err(anyhow!(
                    "upstream with the hostname {} declared more than once",
                    cfg.hostname
                ));
            }
        }

        Ok(Self { by_name, by_host })
    }

    pub fn find_by_name(&self, name: &str) -> Option<&ProxyClient> {
        self.by_name.get(name).map(|r| &**r)
    }

    pub fn find_by_host(&self, host: &str) -> Option<&ProxyClient> {
        self.by_host.get(host).map(|r| &**r)
    }
}
