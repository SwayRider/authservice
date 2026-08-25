-- +migrate Up
-- Email-verified MFA/TOTP reset tokens. The pending secret is encrypted the
-- same way as user_mfa.secret (see internal/db/mfa.go) and only takes effect
-- once the emailed link's code-confirmation step succeeds -- the existing
-- user_mfa row (and its enabled flag) is left untouched until then.
CREATE TABLE IF NOT EXISTS mfa_reset_tokens (
    user_id           UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    token             TEXT NOT NULL,
    pending_secret    TEXT NOT NULL,
    pending_secret_key_id TEXT,
    valid_until       TIMESTAMPTZ NOT NULL
);

-- +migrate Down
DROP TABLE mfa_reset_tokens;
