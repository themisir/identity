use std::ops::Add;
use std::str::FromStr;
use anyhow::anyhow;
use chrono::Duration;
use chrono::prelude::*;
use futures::{TryStreamExt};
use rand::distributions::Alphanumeric;
use rand::Rng;
use sqlx::SqlitePool;

pub enum UserRole {
    Default,
    Admin,
}

impl FromStr for UserRole {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "admin" => Ok(UserRole::Admin),
            "default" => Ok(UserRole::Default),
            _ => Err(anyhow!("invalid role name: {}", s))
        }
    }
}

pub struct User {
    pub id: i32,
    pub username: String,
    pub password_hash: String,
    pub role: UserRole,
}

impl User {
    pub(crate) fn create_hash(password: &[u8]) -> argon2::password_hash::Result<String> {
        use argon2::{
            password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
            Argon2,
        };

        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();

        argon2.hash_password(password, &salt).map(|password_hash| password_hash.to_string())
    }

    pub(crate) fn verify_hash(password_hash: &str, password: &[u8]) -> bool {
        use argon2::{
            password_hash::{PasswordHash, PasswordVerifier},
            Argon2,
        };

        match PasswordHash::new(password_hash) {
            Ok(parsed_hash) => Argon2::default()
                .verify_password(password, &parsed_hash)
                .is_ok(),
            Err(_) => false
        }
    }

    pub fn check_password(&self, password: &[u8]) -> bool {
        Self::verify_hash(self.password_hash.as_str(), password)
    }
}

pub struct UserClaim {
    pub name: String,
    pub value: String,
}

pub struct UserStore {
    pool: SqlitePool,
}

impl UserStore {
    fn normalize_username(s: &str) -> (&str, String) {
        let username = s.trim();
        let normalized_username = username.to_uppercase();
        (username, normalized_username)
    }

    pub async fn find_user_by_username(&self, username: &str) -> anyhow::Result<Option<User>> {
        let (_, normalized_username) = Self::normalize_username(username);

        #[derive(sqlx::FromRow)]
        struct Row {
            user_id: i32,
            username: String,
            password_hash: String,
            role_name: String,
        }

        let row = sqlx::query_as::<_, Row>(include_str!("sql/find_user_by_username.sql"))
            .bind(normalized_username)
            .fetch_optional(&self.pool)
            .await?;

        Ok(row.map(|row| User {
            id: row.user_id,
            username: row.username,
            password_hash: row.password_hash,
            role: UserRole::from_str(row.role_name.as_str()).unwrap_or(UserRole::Default),
        }))
    }

    pub async fn get_user_claims(&self, user_id: i32) -> anyhow::Result<Vec<UserClaim>> {
        #[derive(sqlx::FromRow)]
        struct Row {
            claim_name: String,
            claim_value: String,
        }

        let mut stream = sqlx::query_as::<_, Row>(include_str!("sql/get_user_claims.sql"))
            .bind(user_id)
            .fetch(&self.pool);

        let mut claims = Vec::new();

        while let Some(row) = stream.try_next().await? {
            claims.push(UserClaim { name: row.claim_name, value: row.claim_value })
        }

        Ok(claims)
    }

    pub async fn create_user(&self, username: &str, password: &str) -> anyhow::Result<User> {
        let password_hash = User::create_hash(password.as_bytes()).map_err(|err| anyhow!("failed to create hash: {}", err))?;
        let (username, normalized_username) = Self::normalize_username(username);

        #[derive(sqlx::FromRow)]
        struct Row {
            user_id: i32,
            username: String,
            password_hash: String,
            role_name: String,
        }

        let row = sqlx::query_as::<_, Row>(include_str!("sql/create_user.sql"))
            .bind(username)
            .bind(normalized_username)
            .bind(password_hash)
            .fetch_one(&self.pool)
            .await?;

        Ok(User {
            id: row.user_id,
            username: row.username,
            password_hash: row.password_hash,
            role: UserRole::from_str(row.role_name.as_str()).unwrap_or(UserRole::Default),
        })
    }

    pub async fn find_user_by_session(&self, session_id: &str, issuer: Option<&str>) -> anyhow::Result<Option<User>> {
        #[derive(sqlx::FromRow)]
        struct Row {
            issuer: Option<String>,
            expires_at: Option<DateTime<Utc>>,
            user_id: i32,
            username: String,
            password_hash: String,
            role_name: String,
        }

        let row = sqlx::query_as::<_, Row>(include_str!("sql/find_user_by_session.sql"))
            .bind(session_id)
            .fetch_optional(&self.pool)
            .await?;

        match row {
            None => Ok(None),
            Some(row) => {
                if match (issuer, &row.issuer) {
                    (None, _) => true,
                    (Some(i1), Some(i2)) => i2.eq(i1),
                    _ => false
                } {
                    return Err(anyhow!("invalid issuer"));
                }

                Ok(Some(User {
                    id: row.user_id,
                    username: row.username,
                    password_hash: row.password_hash,
                    role: UserRole::from_str(row.role_name.as_str()).unwrap_or(UserRole::Default),
                }))
            }
        }
    }

    pub async fn create_user_session(&self, user_id: i32, issuer: &str, ttl: Option<Duration>) -> anyhow::Result<String> {
        let expires_at = ttl.map(|ttl| Utc::now().add(ttl));
        let session_id: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(7)
            .map(char::from)
            .collect();

        let result = sqlx::query(include_str!("sql/create_user_session.sql"))
            .bind(session_id.clone())
            .bind(user_id)
            .bind(issuer)
            .bind(expires_at)
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 1 {
            Ok(session_id)
        } else {
            Err(anyhow!("unable to create user session: no rows affected"))
        }
    }
}
