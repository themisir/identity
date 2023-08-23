INSERT INTO user_sessions (session_id, user_id, issuer, expires_at)
VALUES (?, ?, ?, ?)
RETURNING session_id