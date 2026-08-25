-- +migrate Up
-- Extra safety check on the email-verified MFA reset flow: clicking the
-- emailed link no longer immediately reveals the new secret's QR code --
-- the account password must be re-verified first (see internal/web/reset_mfa.go).
-- password_verified gates the QR/code-confirmation step; attempts bounds
-- password guessing against a single reset token, mirroring
-- mfa_challenges.attempts for login MFA challenges.
ALTER TABLE mfa_reset_tokens
    ADD COLUMN password_verified BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN attempts INT NOT NULL DEFAULT 0;

-- +migrate Down
ALTER TABLE mfa_reset_tokens
    DROP COLUMN password_verified,
    DROP COLUMN attempts;
