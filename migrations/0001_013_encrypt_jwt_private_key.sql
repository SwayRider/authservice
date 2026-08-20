-- +migrate Up
-- Adds encryption-at-rest support for jwt_keys.private_key. When
-- private_key_encrypted is true, private_key holds a base64-encoded
-- AES-256-GCM blob (nonce || ciphertext || tag) instead of a plaintext PEM
-- key, and encryption_key_id identifies (by fingerprint, never the key
-- itself) which configured master key it was encrypted under. Existing rows
-- default to private_key_encrypted = false, so they remain readable as
-- plaintext PEM without any backfill -- see internal/db/jwt_keys.go.
ALTER TABLE jwt_keys ADD COLUMN private_key_encrypted BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE jwt_keys ADD COLUMN encryption_key_id TEXT;

-- +migrate Down
ALTER TABLE jwt_keys DROP COLUMN encryption_key_id;
ALTER TABLE jwt_keys DROP COLUMN private_key_encrypted;
