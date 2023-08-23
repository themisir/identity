use std::{net::SocketAddr, path::Path};

use serde::{Deserialize, Serialize};

#[derive(Clone)]
pub struct AppState {
    pub config: Box<AppConfig>,
}

impl AppState {
    pub async fn from_config(config: AppConfig) -> anyhow::Result<Self> {
        Ok(AppState{
            config: Box::new(config)
        })
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AppConfig {
    pub bind: SocketAddr,
    pub base_url: String,
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
