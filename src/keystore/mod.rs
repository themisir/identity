mod ring;

use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::Engine;
use chrono::{DateTime, TimeDelta};
use jsonwebtoken::{jwk, Algorithm, DecodingKey, EncodingKey, Validation};
use omnom::prelude::*;
use openssl::{pkey::Private, rsa::Rsa};
use serde::{de::DeserializeOwned, Serialize};
use std::fs::{read_dir, File};
use std::io::{Read, Write};
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};
use uuid::Uuid;

use crate::keystore::ring::FixedSizeRing;

const RSA_KEY_SIZE: u32 = 2048;
const JWT_ALGORITHM: Algorithm = Algorithm::RS256;
const KEYSTORE_EXTENSION: &str = "idkpv1"; // Identity KeyPair v1

pub struct Keystore {
    inner: Arc<RwLock<Inner>>,
    fs_lock: Arc<Mutex<()>>,
    fs_dir: Option<String>,
}

impl Keystore {
    pub fn new(max_key_age: TimeDelta) -> Keystore {
        Keystore {
            inner: Arc::new(RwLock::new(Inner {
                keys: Default::default(),
                jwks: jwk::JwkSet { keys: Vec::new() },
                max_key_age,
            })),
            fs_lock: Arc::new(Mutex::new(())),
            fs_dir: None,
        }
    }

    pub fn use_directory(&mut self, dir: String) {
        let mut inner = self.inner.write().unwrap();
        if let Err(err) = inner.load_from_dir(&dir) {
            log::error!("Unable to load keystore from fs: {}", err);
        }

        self.fs_dir = Some(dir);
    }

    fn updated(&self) {
        if let Some(fs_dir) = self.fs_dir.clone() {
            let inner = self.inner.clone();
            let fs_lock = self.fs_lock.clone();

            tokio::spawn(async move {
                let lock = fs_lock.lock().unwrap();
                let inner = inner.read().unwrap();

                if let Err(err) = inner.save_to_dir(fs_dir) {
                    log::error!("Unable to save keystore into fs: {}", err);
                }

                drop(lock);
            });
        }
    }

    pub fn jwt_encode<T: Serialize>(&self, claims: T) -> jsonwebtoken::errors::Result<String> {
        let optimistic_guard = self.inner.read().unwrap();
        if let Some(key) = optimistic_guard.find_encryption_key() {
            return key.jwt_encode(claims);
        }
        drop(optimistic_guard);

        let mut pessimistic_guard = self.inner.write().unwrap();
        if let Some(key) = pessimistic_guard.find_encryption_key() {
            key.jwt_encode(claims)
        } else {
            let token = pessimistic_guard.regenerate_key().jwt_encode(claims);
            self.updated();
            token
        }
    }

    pub fn jwt_decode<T: DeserializeOwned>(
        &self,
        token: &str,
        validation: &Validation,
    ) -> anyhow::Result<T> {
        let inner = self.inner.read().unwrap();

        let header = jsonwebtoken::decode_header(token)?;
        let keypair = header
            .kid
            .and_then(|kid| inner.keys.iter().find(|&k| k.key_id() == kid));

        if let Some(keypair) = keypair {
            Ok(keypair.jwt_decode(token, validation)?)
        } else {
            anyhow::bail!("JWT key id is not found")
        }
    }
}

struct Inner {
    keys: FixedSizeRing<Keypair, 3>,
    jwks: jwk::JwkSet,
    max_key_age: TimeDelta,
}

impl Inner {
    fn save_to_dir<P: AsRef<Path>>(&self, path: P) -> anyhow::Result<()> {
        for (i, key) in self.keys.iter().enumerate() {
            let file_path = path
                .as_ref()
                .join(format!("rsakey_{i}.{KEYSTORE_EXTENSION}"));
            let mut file = File::create(file_path)?;
            key.write_to(&mut file)?;
        }

        Ok(())
    }

    fn load_from_dir<P: AsRef<Path>>(&mut self, path: P) -> anyhow::Result<()> {
        let mut modified = false;

        for item in read_dir(path)?.filter_map(|x| x.ok()) {
            if let Ok(ft) = item.file_type() {
                if !ft.is_file() {
                    continue;
                }
            } else {
                continue;
            }

            if let Some(ext) = item.path().extension() {
                if ext == KEYSTORE_EXTENSION {
                    log::info!(
                        "Loading keypair from file '{}'",
                        item.path().to_str().unwrap_or("")
                    );

                    let mut file = File::open(item.path())?;
                    let keypair = Keypair::read_from(&mut file)?;

                    self.keys.push(keypair);
                    modified = true;
                }
            }
        }

        if modified {
            self.regenerate_jwks();
        }

        Ok(())
    }

    pub fn regenerate_key(&mut self) -> &Keypair {
        self.keys.push(Keypair::generate());
        self.regenerate_jwks();
        self.keys
            .last_pushed()
            .expect("an item must have been inserted")
    }

    pub fn regenerate_jwks(&mut self) {
        self.jwks.keys.clear();
        self.keys
            .iter()
            .map(|k| k.to_jwk())
            .collect_into(&mut self.jwks.keys);
    }

    fn find_encryption_key(&self) -> Option<&Keypair> {
        self.keys.iter().find(|&k| k.age() > self.max_key_age)
    }
}

pub struct Jwks<'a>(pub &'a Keystore);

impl<'a> IntoResponse for Jwks<'a> {
    fn into_response(self) -> Response {
        let inner = self.0.inner.read().unwrap();
        Json(&inner.jwks).into_response()
    }
}

struct Keypair {
    jwt_header: jsonwebtoken::Header,
    rsa_keys: Rsa<Private>,
    enc_key: EncodingKey,
    dec_key: DecodingKey,
    issued_at: DateTime<chrono::Utc>,
}

impl Keypair {
    pub fn write_to<W: Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        #[inline]
        fn write_bytes<W: Write>(writer: &mut W, buf: &[u8]) -> std::io::Result<()> {
            writer.write_le(buf.len() as u32)?;
            writer.write_all(buf)
        }

        write_bytes(writer, self.key_id().as_bytes())?;
        writer.write_le(self.issued_at.timestamp())?;
        write_bytes(writer, &self.rsa_keys.private_key_to_der()?)?;

        Ok(())
    }

    pub fn read_from<R: Read>(reader: &mut R) -> anyhow::Result<Self> {
        #[inline]
        fn read_bytes<R: Read>(reader: &mut R) -> std::io::Result<Vec<u8>> {
            let size: u32 = reader.read_le()?;
            let mut buffer = vec![0; size as usize];
            reader.read_exact(&mut buffer)?;
            Ok(buffer)
        }

        let kid_bytes = read_bytes(reader)?;
        let timestamp: i64 = reader.read_le()?;
        let key_bytes = read_bytes(reader)?;

        let key_id = String::from_utf8(kid_bytes)?;

        let issued_at = DateTime::from_timestamp(timestamp, 0)
            .ok_or(anyhow::format_err!("invalid timestamp '{}'", timestamp))?;

        let rsa_keys = Rsa::private_key_from_der(&key_bytes)?;

        Ok(Self::from_rsa(key_id, rsa_keys, issued_at))
    }

    pub fn from_rsa(
        key_id: String,
        rsa_keys: Rsa<Private>,
        issued_at: DateTime<chrono::Utc>,
    ) -> Self {
        let private_key_pem = rsa_keys
            .private_key_to_pem()
            .expect("Failed to extract private key to PEM.");
        let public_key_pem = rsa_keys
            .public_key_to_pem()
            .expect("Failed to extract public key to PEM.");

        let enc_key = EncodingKey::from_rsa_pem(&private_key_pem).unwrap();
        let dec_key = DecodingKey::from_rsa_pem(&public_key_pem).unwrap();

        let mut jwt_header = jsonwebtoken::Header::new(JWT_ALGORITHM);
        jwt_header.kid = Some(key_id);

        Keypair {
            jwt_header,
            rsa_keys,
            enc_key,
            dec_key,
            issued_at,
        }
    }

    pub fn generate() -> Self {
        let key_id = Uuid::new_v4().to_string();
        let rsa_keys = Rsa::generate(RSA_KEY_SIZE).expect("Failed to generate RSA keys");
        let issued_at = chrono::Utc::now();

        Self::from_rsa(key_id, rsa_keys, issued_at)
    }

    pub fn key_id(&self) -> &str {
        self.jwt_header
            .kid
            .as_ref()
            .expect("jwt header key id must have been set")
    }

    pub fn age(&self) -> TimeDelta {
        chrono::Utc::now() - self.issued_at
    }

    pub fn jwt_encode<T: Serialize>(&self, claims: T) -> jsonwebtoken::errors::Result<String> {
        jsonwebtoken::encode(&self.jwt_header, &claims, &self.enc_key)
    }

    pub fn jwt_decode<T: DeserializeOwned>(
        &self,
        token: &str,
        validation: &Validation,
    ) -> jsonwebtoken::errors::Result<T> {
        jsonwebtoken::decode(token, &self.dec_key, validation).map(|data| data.claims)
    }

    pub(crate) fn to_jwk(&self) -> jwk::Jwk {
        use jwk::*;

        Jwk {
            common: CommonParameters {
                key_id: self.jwt_header.kid.clone(),
                public_key_use: Some(PublicKeyUse::Signature),
                key_operations: Some(vec![KeyOperations::Verify, KeyOperations::Sign]),
                key_algorithm: Some(KeyAlgorithm::RS256),
                ..Default::default()
            },
            algorithm: AlgorithmParameters::RSA(RSAKeyParameters {
                key_type: RSAKeyType::RSA,
                n: base64::engine::general_purpose::URL_SAFE.encode(self.rsa_keys.n().to_vec()),
                e: base64::engine::general_purpose::URL_SAFE.encode(self.rsa_keys.e().to_vec()),
            }),
        }
    }
}
