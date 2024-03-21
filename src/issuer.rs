use std::collections::HashMap;

use axum::{
    extract::State,
    response::{IntoResponse, Response},
    Json,
};
use chrono::{Duration, TimeDelta};
use jsonwebtoken::{Algorithm, Validation};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::app::AppState;
use crate::keystore::{Jwks, Keystore};
use crate::store::{User, UserClaim};

#[derive(Serialize, Deserialize)]
pub struct Claims {
    pub iss: String,
    pub aud: String,
    pub sub: String,
    pub iat: i64,
    pub exp: i64,
    pub nbf: i64,

    // extras
    pub name: String,
    #[serde(flatten)]
    pub extra: HashMap<String, String>,
}

impl Claims {
    pub fn valid_for(&self) -> Duration {
        Duration::seconds(self.exp - chrono::Utc::now().timestamp())
    }
}

pub struct Issuer {
    issuer: String,
    discovery: DiscoverySpecs,
    keystore: Keystore,
    validation: Validation,
}

#[derive(Serialize)]
struct DiscoverySpecs {
    issuer: String,
    authorization_endpoint: String,
    revocation_endpoint: String,
    jwks_uri: String,
    id_token_signing_alg_values_supported: Vec<Algorithm>,
}

type Result<T> = jsonwebtoken::errors::Result<T>;

impl Issuer {
    pub fn new(issuer: Url, keystore_dir: Option<String>) -> Self {
        let issuer = issuer.origin().ascii_serialization();

        let discovery = DiscoverySpecs {
            issuer: issuer.clone(),
            authorization_endpoint: format!("{}/authorize", issuer),
            revocation_endpoint: format!("{}/logout", issuer),
            jwks_uri: format!("{}/.well-known/jwks", issuer),
            id_token_signing_alg_values_supported: vec![Algorithm::RS256],
        };

        let mut keystore = Keystore::new(TimeDelta::days(30));
        if let Some(keystore_dir) = keystore_dir {
            keystore.use_directory(keystore_dir);
        }

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&issuer]);
        validation.validate_exp = true;
        validation.validate_nbf = true;

        Self {
            issuer,
            keystore,
            discovery,
            validation,
        }
    }

    pub fn validate_token(&self, token: &str) -> anyhow::Result<Claims> {
        self.keystore.jwt_decode(token, &self.validation)
    }

    pub fn create_token(
        &self,
        aud: &str,
        user: &User,
        claims: &[UserClaim],
        ttl: Duration,
    ) -> Result<String> {
        let now = chrono::Utc::now();
        let expires = now + ttl;

        let mut extra = HashMap::new();
        for claim in claims {
            extra.insert(claim.name.clone(), claim.value.clone());
        }

        let claims = Claims {
            iss: self.issuer.clone(),
            aud: aud.into(),
            sub: format!("{}", user.id),
            iat: now.timestamp(),
            nbf: now.timestamp(),
            exp: expires.timestamp(),
            name: user.username.clone(),
            extra,
        };

        self.keystore.jwt_encode(claims)
    }
}

#[axum_macros::debug_handler]
pub async fn jwk_handler(State(state): State<AppState>) -> Response {
    Jwks(&state.issuer().keystore).into_response()
}

#[axum_macros::debug_handler]
pub async fn discovery_handler(State(state): State<AppState>) -> Response {
    Json(&state.issuer().discovery).into_response()
}
