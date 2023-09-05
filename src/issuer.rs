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
    AlgorithmParameters, CommonParameters, Jwk, JwkSet, KeyOperations, PublicKeyUse,
    RSAKeyParameters, RSAKeyType,
};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Validation};
use openssl::rsa::Rsa;
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Serialize, Deserialize)]
pub struct Claims {
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

    jwk_set: JwkSet,
    discovery: DiscoverySpecs,
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
    pub fn new(issuer: Url) -> Self {
        let algorithm = Algorithm::RS256;
        let mut header = jsonwebtoken::Header::new(algorithm);

        let rsa_keys = Rsa::generate(2048).expect("Failed to generate RSA keys.");
        let private_key_pem = rsa_keys
            .private_key_to_pem()
            .expect("Failed to extract private key to PEM.");
        let public_key_pem = rsa_keys
            .public_key_to_pem()
            .expect("Failed to extract public key to PEM.");

        let encoding_key = EncodingKey::from_rsa_pem(&private_key_pem).unwrap();
        let decoding_key = DecodingKey::from_rsa_pem(&public_key_pem).unwrap();

        let validation = Validation::new(algorithm);

        let kid = format!("idk{}", chrono::Utc::now().timestamp());

        let jwk_set = JwkSet {
            keys: vec![Jwk {
                common: CommonParameters {
                    key_id: Some(kid.clone()),
                    public_key_use: Some(PublicKeyUse::Signature),
                    key_operations: Some(vec![KeyOperations::Verify, KeyOperations::Sign]),
                    algorithm: Some(Algorithm::RS256),
                    ..Default::default()
                },
                algorithm: AlgorithmParameters::RSA(RSAKeyParameters {
                    key_type: RSAKeyType::RSA,
                    n: base64::engine::general_purpose::STANDARD.encode(rsa_keys.n().to_vec()),
                    e: base64::engine::general_purpose::STANDARD.encode(rsa_keys.e().to_vec()),
                }),
            }],
        };

        let issuer = issuer.origin().ascii_serialization();

        let discovery = DiscoverySpecs {
            issuer: issuer.clone(),
            authorization_endpoint: format!("{}/authorize", issuer),
            revocation_endpoint: format!("{}/logout", issuer),
            jwks_uri: format!("{}/.well-known/jwks", issuer),
            id_token_signing_alg_values_supported: vec![Algorithm::RS256],
        };

        header.kid = Some(kid);

        Self {
            header,
            encoding_key,
            decoding_key,
            validation,
            issuer,

            jwk_set,
            discovery,
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
    Json(&state.issuer().jwk_set).into_response()
}

#[axum_macros::debug_handler]
pub async fn discovery_handler(State(state): State<AppState>) -> Response {
    Json(&state.issuer().discovery).into_response()
}
