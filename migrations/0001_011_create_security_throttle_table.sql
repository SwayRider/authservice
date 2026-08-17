-- +migrate Up
-- Shared table backing two defense-in-depth controls:
--   - account-level lockout on Login/GetToken after repeated failures
--     (attempt_count/window_start/locked_until)
--   - per-email cooldown on endpoints that send outbound mail
--     (last_attempt_at only)
-- The `scope` column keeps the two concerns from ever sharing a row even
-- though they share a table (e.g. "login" vs "email_password_reset").
CREATE TABLE IF NOT EXISTS security_throttle (
    scope           TEXT NOT NULL,
    identifier      TEXT NOT NULL,
    attempt_count   INT NOT NULL DEFAULT 0,
    window_start    TIMESTAMPTZ NOT NULL DEFAULT now(),
    locked_until    TIMESTAMPTZ,
    last_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (scope, identifier)
);

CREATE INDEX idx_security_throttle_last_attempt ON security_throttle (last_attempt_at);

-- +migrate Down
DROP TABLE security_throttle;
