use crate::app::{AppState, UpstreamConfig};
use axum::{
    extract::{Host, State},
    http::{uri, Request, StatusCode, Uri},
    middleware::Next,
    response::{IntoResponse, Response},
};
use hyper::{client::HttpConnector, Body};
use hyper_tls::HttpsConnector;
use log::{error, info};
use std::str::FromStr;

pub async fn middleware(
    State(state): State<AppState>,
    Host(host): Host,
    request: Request<Body>,
    next: Next<Body>,
) -> Result<Response, StatusCode> {
    let state = state.read().await;
    let upstream = {
        let host = host.to_lowercase();
        state.upstreams.get(host.as_str())
    };

    match upstream {
        None => Ok(next.run(request).await),
        Some(client) => client.handle(request).await.map_err(|err| {
            error!(
                "[{}] failed to handle proxy request: {}",
                client.name(),
                err
            );
            StatusCode::SERVICE_UNAVAILABLE
        }),
    }
}

pub struct ProxyClient {
    config: UpstreamConfig,
    client: hyper::Client<HttpsConnector<HttpConnector>>,
    host: Uri,
}

const COOKIE_NAME: &str = "_identity.im";

impl ProxyClient {
    pub fn new(config: &UpstreamConfig) -> anyhow::Result<Self> {
        info!(
            "create upstream client {} for {}",
            config.name, config.hostname
        );

        let https = HttpsConnector::new();
        let client = hyper::Client::builder().build::<_, hyper::Body>(https);
        let host = Uri::from_str(config.target_url.as_str())?;

        Ok(Self {
            config: config.clone(),
            client,
            host,
        })
    }

    pub fn name(&self) -> &str {
        self.config.name.as_str()
    }

    pub async fn handle(&self, request: Request<Body>) -> anyhow::Result<Response> {
        // let cookies = Cookies::from_headers(request.headers());
        // let cookie = cookies.get(COOKIE_NAME);
        // if let Some(cookie) = cookie {
        //     cookie.value()
        // }

        self.forward(request).await
    }

    async fn forward(&self, mut request: Request<Body>) -> anyhow::Result<Response> {
        let mut parts = self.host.clone().into_parts();
        parts.path_and_query = request.uri().path_and_query().map(uri::PathAndQuery::clone);

        let uri = Uri::from_parts(parts)?;
        info!("Forwarding {} to {}", request.uri(), uri);
        *request.uri_mut() = uri;

        Ok(self.client.request(request).await?.into_response())
    }
}
