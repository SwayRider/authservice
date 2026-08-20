-- +migrate Up
-- Stores the last PASSWORD_HISTORY_SIZE Argon2id password hashes per user so
-- password change and reset can reject reuse of a recent password. Hashes are
-- the same format as users.password_hash. See internal/db/password_history.go.
CREATE TABLE IF NOT EXISTS password_history (
    id            BIGSERIAL PRIMARY KEY,
    user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    password_hash TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Covers both the per-user newest-N lookup/trim and the global cleanup sweep.
CREATE INDEX idx_password_history_user_id ON password_history (user_id, created_at DESC, id DESC);

-- +migrate Down
DROP TABLE password_history;
