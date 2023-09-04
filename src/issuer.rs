use crate::app::AppState;
use crate::store::{User, UserClaim};
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use base64::Engine;
use chrono::Duration;
use jsonwebtoken::jwk::{
    AlgorithmParameters, CommonParameters, Jwk, JwkSet, KeyOperations, OctetKeyParameters,
    OctetKeyType, PublicKeyUse,
};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Validation};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use axum::Json;

#[derive(Serialize, Deserialize)]
pub struct Claims {
    iss: String,
    aud: String,
    sub: String,
    iat: i64,
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
    jwk_set: JwkSet,
    issuer: String,
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

        let jwk_set = JwkSet {
            keys: vec![Jwk {
                common: CommonParameters {
                    public_key_use: Some(PublicKeyUse::Signature),
                    key_operations: Some(vec![KeyOperations::Verify]),
                    algorithm: Some(Algorithm::EdDSA),
                    key_id: None,
                    ..Default::default()
                },
                algorithm: AlgorithmParameters::OctetKey(OctetKeyParameters {
                    key_type: OctetKeyType::Octet,
                    value: base64::engine::general_purpose::STANDARD.encode(doc.as_ref()),
                }),
            }],
        };

        Self {
            header,
            encoding_key,
            decoding_key,
            validation,
            jwk_set,
            issuer: issuer.into(),
        }
    }

    pub fn jwk_set(&self) -> &JwkSet {
        &self.jwk_set
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
            iss: self.issuer.clone(),
            aud: aud.into(),
            sub: format!("{}", user.id),
            iat: now.timestamp(),
            nbf: expires.timestamp(),
            name: user.username.clone(),
            extra,
        };

        jsonwebtoken::encode(&self.header, &claims, &self.encoding_key)
    }
}

#[axum_macros::debug_handler]
pub async fn jwks(State(state): State<AppState>) -> Response {
    let state = state.read().await;
    Json(state.issuer.jwk_set()).into_response()
}
