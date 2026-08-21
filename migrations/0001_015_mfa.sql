-- +migrate Up
-- TOTP second-factor enrollment. secret holds an AES-256-GCM blob (base64)
-- keyed by ENCRYPTION_MASTER_KEY; secret_key_id is the KeyRing fingerprint
-- so ENCRYPTION_MASTER_KEY_PREVIOUS rotation keeps working (mirrors jwt_keys).
CREATE TABLE IF NOT EXISTS user_mfa (
    id            BIGSERIAL PRIMARY KEY,
    user_id       UUID UNIQUE NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    enabled       BOOLEAN NOT NULL DEFAULT false,
    secret        TEXT NOT NULL,
    secret_key_id TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Single-use backup codes, Argon2id-hashed. Codes are consumed atomically.
CREATE TABLE IF NOT EXISTS mfa_backup_codes (
    id         BIGSERIAL PRIMARY KEY,
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash  TEXT NOT NULL,
    used       BOOLEAN NOT NULL DEFAULT false,
    used_at    TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_mfa_backup_codes_user ON mfa_backup_codes (user_id);

-- Pending-login challenge tokens: raw token never stored, only SHA-256.
-- One live challenge per user (new login deletes the previous one).
CREATE TABLE IF NOT EXISTS mfa_challenges (
    id          BIGSERIAL PRIMARY KEY,
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash  TEXT NOT NULL,
    attempts    INT NOT NULL DEFAULT 0,
    valid_until TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_mfa_challenges_token ON mfa_challenges (token_hash);

-- +migrate Down
DROP TABLE mfa_challenges;
DROP TABLE mfa_backup_codes;
DROP TABLE user_mfa;
