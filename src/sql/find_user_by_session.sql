SELECT s.issuer, s.expires_at, u.id as user_id, u.username, u.password_hash, u.role_name
FROM user_sessions s
         JOIN users u ON s.user_id = u.id
WHERE s.session_id = ?