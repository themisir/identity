CREATE TABLE users
(
    id                  INTEGER   NOT NULL PRIMARY KEY AUTOINCREMENT,
    username            TEXT      NOT NULL,
    username_normalized TEXT      NOT NULL,
    password_hash       TEXT      NOT NULL,
    role_name           TEXT      NOT NULL DEFAULT 'User',
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE user_claims
(
    id          INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL,
    claim_name  TEXT    NOT NULL,
    claim_value TEXT    NOT NULL,

    FOREIGN KEY (user_id) REFERENCES users (id)
        ON UPDATE CASCADE
        ON DELETE CASCADE
);

CREATE TABLE user_sessions
(
    session_id TEXT      NOT NULL PRIMARY KEY,
    user_id    TEXT      NOT NULL,
    issuer     TEXT      NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NULL,

    FOREIGN KEY (user_id) REFERENCES users (id)
        ON UPDATE CASCADE
        ON DELETE CASCADE
);