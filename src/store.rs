use crate::app::AppConfig;

use std::fmt::{Display, Formatter};
use std::str::FromStr;

use chrono::{prelude::*, Duration};
use futures::TryStreamExt;
use rand::{distributions, Rng};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

#[derive(Serialize, Deserialize, Debug, Copy, Clone, PartialEq)]
pub enum UserRole {
    User,
    Admin,
}

impl UserRole {
    pub fn as_static_str(&self) -> &'static str {
        match self {
            UserRole::User => "user",
            UserRole::Admin => "admin",
        }
    }
}

impl Display for UserRole {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_static_str())
    }
}

impl FromStr for UserRole {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "admin" => Ok(UserRole::Admin),
            "user" | "default" => Ok(UserRole::User),
            _ => anyhow::bail!("invalid role name: {}", s),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
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

        argon2
            .hash_password(password, &salt)
            .map(|password_hash| password_hash.to_string())
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
            Err(_) => false,
        }
    }

    pub fn check_password(&self, password: &[u8]) -> bool {
        Self::verify_hash(self.password_hash.as_str(), password)
    }
}

#[derive(Clone)]
pub struct UserClaim {
    pub name: String,
    pub value: String,
}

mod embedded {
    use refinery::embed_migrations;
    embed_migrations!("./src/migrations");
}

pub async fn migrate(config: &AppConfig) -> anyhow::Result<()> {
    use refinery::config::*;

    let db_path = config.users_db.as_str()[config.users_db.scheme().len()..]
        .trim_start_matches(':')
        .trim_start_matches("//")
        .to_string();

    // make sure file exists
    drop(std::fs::File::create_new(db_path.as_str()));

    let mut conf = Config::new(ConfigDbType::Sqlite).set_db_path(db_path.as_str());

    embedded::migrations::runner().run(&mut conf)?;

    Ok(())
}

#[derive(Clone)]
pub struct UserStore {
    pool: SqlitePool,
}

impl UserStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    fn normalize_username(s: &str) -> (&str, String) {
        let username = s.trim();
        let normalized_username = username.to_uppercase();
        (username, normalized_username)
    }

    fn get_pool(&self) -> &SqlitePool {
        &self.pool
    }

    pub async fn find_user_by_username(&self, username: &str) -> anyhow::Result<Option<User>> {
        let (_, normalized_username) = Self::normalize_username(username);

        #[derive(sqlx::FromRow)]
        struct Row {
            id: i32,
            username: String,
            password_hash: String,
            role_name: String,
        }

        let row = sqlx::query_as::<_, Row>(include_str!("sql/find_user_by_username.sql"))
            .bind(normalized_username)
            .fetch_optional(self.get_pool())
            .await?;

        Ok(row.map(|row| User {
            id: row.id,
            username: row.username,
            password_hash: row.password_hash,
            role: UserRole::from_str(row.role_name.as_str()).unwrap_or(UserRole::User),
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
            .fetch(self.get_pool());

        let mut claims = Vec::new();

        while let Some(row) = stream.try_next().await? {
            claims.push(UserClaim {
                name: row.claim_name,
                value: row.claim_value,
            })
        }

        Ok(claims)
    }

    pub async fn create_user(
        &self,
        username: &str,
        password: &str,
        role: UserRole,
    ) -> anyhow::Result<User> {
        let password_hash = User::create_hash(password.as_bytes())
            .map_err(|err| anyhow::format_err!("failed to create hash: {}", err))?;
        let (username, normalized_username) = Self::normalize_username(username);
        let role_name = role.as_static_str();

        #[derive(sqlx::FromRow)]
        struct Row {
            id: i32,
            username: String,
            password_hash: String,
            role_name: String,
        }

        let row = sqlx::query_as::<_, Row>(include_str!("sql/create_user.sql"))
            .bind(username)
            .bind(normalized_username)
            .bind(password_hash)
            .bind(role_name)
            .fetch_one(self.get_pool())
            .await?;

        Ok(User {
            id: row.id,
            username: row.username,
            password_hash: row.password_hash,
            role: UserRole::from_str(row.role_name.as_str()).unwrap_or(UserRole::User),
        })
    }

    pub async fn find_user_by_session(
        &self,
        session_id: &str,
        issuer: Option<&str>,
    ) -> anyhow::Result<Option<User>> {
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
            .fetch_optional(self.get_pool())
            .await?;

        match row {
            None => Ok(None),
            Some(row) => {
                if match (issuer, &row.issuer) {
                    (None, _) => false,               // issuer check is not needed
                    (Some(i1), Some(i2)) => i2 != i1, // check issuer
                    (Some(..), None) => true, // issuer check needed, but not set for the token
                } {
                    anyhow::bail!("invalid issuer");
                }

                if let Some(expires_at) = row.expires_at {
                    if Utc::now() > expires_at {
                        anyhow::bail!("expired session")
                    }
                }

                Ok(Some(User {
                    id: row.user_id,
                    username: row.username,
                    password_hash: row.password_hash,
                    role: UserRole::from_str(row.role_name.as_str()).unwrap_or(UserRole::User),
                }))
            }
        }
    }

    pub async fn create_user_session(
        &self,
        user_id: i32,
        issuer: &str,
        ttl: Option<Duration>,
    ) -> anyhow::Result<String> {
        let expires_at = ttl.map(|ttl| Utc::now() + ttl);
        let session_id: String = rand::thread_rng()
            .sample_iter(&distributions::Alphanumeric)
            .take(32)
            .map(char::from)
            .collect();

        let result = sqlx::query(include_str!("sql/create_user_session.sql"))
            .bind(session_id.clone())
            .bind(user_id)
            .bind(issuer)
            .bind(expires_at)
            .execute(self.get_pool())
            .await?;

        if result.rows_affected() == 1 {
            Ok(session_id)
        } else {
            anyhow::bail!("unable to create user session: no rows affected")
        }
    }

    pub async fn get_all_users(&self) -> anyhow::Result<Vec<User>> {
        #[derive(sqlx::FromRow)]
        struct Row {
            id: i32,
            username: String,
            password_hash: String,
            role_name: String,
        }

        let mut stream =
            sqlx::query_as::<_, Row>(include_str!("sql/get_all_users.sql")).fetch(self.get_pool());

        let mut users = Vec::new();

        while let Some(row) = stream.try_next().await? {
            users.push(User {
                id: row.id,
                username: row.username,
                password_hash: row.password_hash,
                role: UserRole::from_str(&row.role_name).unwrap_or(UserRole::User),
            })
        }

        Ok(users)
    }

    pub async fn add_user_claim(&self, user_id: i32, claim: UserClaim) -> anyhow::Result<bool> {
        let result = sqlx::query(include_str!("sql/add_user_claim.sql"))
            .bind(user_id)
            .bind(claim.name)
            .bind(claim.value)
            .execute(self.get_pool())
            .await?;

        Ok(result.rows_affected() > 0)
    }

    pub async fn delete_user_claim_by_name(
        &self,
        user_id: i32,
        claim_name: &str,
    ) -> anyhow::Result<bool> {
        let result = sqlx::query(include_str!("sql/delete_user_claim_by_name.sql"))
            .bind(user_id)
            .bind(claim_name)
            .execute(self.get_pool())
            .await?;

        Ok(result.rows_affected() > 0)
    }

    pub async fn update_user_role(&self, user_id: i32, role: UserRole) -> anyhow::Result<bool> {
        let result = sqlx::query(include_str!("sql/update_user_role.sql"))
            .bind(role.as_static_str())
            .bind(user_id)
            .execute(self.get_pool())
            .await?;

        Ok(result.rows_affected() > 0)
    }
}
