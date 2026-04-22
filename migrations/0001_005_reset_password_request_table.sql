-- +migrate Up
CREATE TABLE IF NOT EXISTS reset_password_tokens (
    user_id UUID PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    token TEXT NOT NULL,
    valid_until TIMESTAMPTZ NOT NULL
);

-- +migrate Down
DROP TABLE reset_password_tokens;
