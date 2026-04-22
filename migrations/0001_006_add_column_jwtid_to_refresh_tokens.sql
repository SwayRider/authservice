-- +migrate Up
ALTER TABLE refresh_tokens ADD COLUMN jwtid VARCHAR(255);

-- +migrate Down
ALTER TABLE refresh_tokens DROP COLUMN jwtid;
