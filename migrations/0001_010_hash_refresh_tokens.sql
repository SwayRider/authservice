-- +migrate Up
-- Refresh tokens were previously stored in plaintext in the `token` column.
-- Renamed to `token_hash` to reflect that only the SHA-256 hex digest of
-- the token is stored going forward (see internal/model.HashToken). The
-- existing unique index remains valid on the renamed column; only its
-- semantics change.
--
-- IMPORTANT: this does NOT rewrite existing rows. Any refresh token issued
-- before this migration deploys still holds its plaintext value here, and
-- post-deploy code only ever queries by SHA-256(presented token), so no
-- pre-migration row will match again. This is intentional -- it is not
-- possible to retroactively "hash" a value that should never have been
-- plaintext -- and it invalidates every currently-active refresh token /
-- "remember me" session as a one-time effect of this deploy. This is
-- expected, not a bug: call it out in deploy/release notes.
ALTER TABLE refresh_tokens RENAME COLUMN token TO token_hash;

-- +migrate Down
ALTER TABLE refresh_tokens RENAME COLUMN token_hash TO token;
