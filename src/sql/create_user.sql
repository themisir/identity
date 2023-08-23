INSERT INTO users (username, username_normalized, password_hash)
VALUES (?, ?, ?)
RETURNING id, username, password_hash, role_name