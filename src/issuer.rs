use crate::app::AppState;
use crate::store::{User, UserClaim};

use std::collections::HashMap;

use axum::{
    extract::State,
    response::{IntoResponse, Response},
    Json,
};
use base64::Engine;
use chrono::Duration;
use jsonwebtoken::jwk::{
    AlgorithmParameters, CommonParameters, Jwk, JwkSet, KeyOperations, OctetKeyParameters,
    OctetKeyType, PublicKeyUse,
};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Validation};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct Claims {
    kid: String,
    iss: String,
    aud: String,
    sub: String,
    iat: i64,
    exp: i64,
    nbf: i64,

    // extras
    name: String,
    #[serde(flatten)]
    extra: HashMap<String, String>,
}

pub struct Issuer {
    header: jsonwebtoken::Header,
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    validation: Validation,
    issuer: String,

    kid: String,
    jwk_set: JwkSet,
    discovery: DiscoverySpecs,
}

#[derive(Serialize)]
struct DiscoverySpecs {
    issuer: String,
    authorization_endpoint: String,
    jwks_uri: String,
    id_token_signing_alg_values_supported: Vec<Algorithm>,
}

type Result<T> = jsonwebtoken::errors::Result<T>;

impl Issuer {
    pub fn new(issuer: &str) -> Self {
        let header = jsonwebtoken::Header::new(Algorithm::EdDSA);

        let doc = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
        let encoding_key = EncodingKey::from_ed_der(doc.as_ref());

        let pair = Ed25519KeyPair::from_pkcs8(doc.as_ref()).unwrap();
        let decoding_key = DecodingKey::from_ed_der(pair.public_key().as_ref());

        let validation = Validation::new(Algorithm::EdDSA);

        let kid = format!("idk{}", chrono::Utc::now().timestamp());

        let jwk_set = JwkSet {
            keys: vec![Jwk {
                common: CommonParameters {
                    key_id: Some(kid.clone()),
                    public_key_use: Some(PublicKeyUse::Signature),
                    key_operations: Some(vec![KeyOperations::Verify, KeyOperations::Sign]),
                    algorithm: Some(Algorithm::EdDSA),
                    ..Default::default()
                },
                algorithm: AlgorithmParameters::OctetKey(OctetKeyParameters {
                    key_type: OctetKeyType::Octet,
                    value: base64::engine::general_purpose::STANDARD.encode(doc.as_ref()),
                }),
            }],
        };

        let discovery = DiscoverySpecs {
            issuer: issuer.into(),
            authorization_endpoint: format!("{}/authorize", issuer),
            jwks_uri: format!("{}/.well-known/jwks", issuer),
            id_token_signing_alg_values_supported: vec![Algorithm::EdDSA],
        };

        Self {
            header,
            encoding_key,
            decoding_key,
            validation,
            issuer: issuer.into(),

            jwk_set,
            discovery,
            kid,
        }
    }

    pub fn validate_token(&self, token: &str) -> Result<Claims> {
        let data = jsonwebtoken::decode::<Claims>(token, &self.decoding_key, &self.validation)?;
        Ok(data.claims)
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
            kid: self.kid.clone(),
            iss: self.issuer.clone(),
            aud: aud.into(),
            sub: format!("{}", user.id),
            iat: now.timestamp(),
            nbf: now.timestamp(),
            exp: expires.timestamp(),
            name: user.username.clone(),
            extra,
        };

        jsonwebtoken::encode(&self.header, &claims, &self.encoding_key)
    }
}

#[axum_macros::debug_handler]
pub async fn jwk_handler(State(state): State<AppState>) -> Response {
    let state = state.read().await;
    Json(&state.issuer.jwk_set).into_response()
}

#[axum_macros::debug_handler]
pub async fn discovery_handler(State(state): State<AppState>) -> Response {
    let state = state.read().await;
    Json(&state.issuer.discovery).into_response()
}
