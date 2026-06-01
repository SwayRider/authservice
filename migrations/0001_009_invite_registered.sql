-- +migrate Up
ALTER TABLE registration_invites ADD COLUMN registered BOOLEAN NOT NULL DEFAULT false;

-- +migrate Down
ALTER TABLE registration_invites DROP COLUMN registered;
