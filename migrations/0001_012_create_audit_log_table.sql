-- +migrate Up
-- Records security-relevant authentication events (login, logout, password
-- changes, admin actions, etc.) for incident investigation and audit trail
-- purposes. Written asynchronously by internal/server.AuditWriter -- see
-- internal/db/audit.go for the accessor.
CREATE TABLE IF NOT EXISTS audit_log (
    id          BIGSERIAL PRIMARY KEY,
    event_type  TEXT NOT NULL,
    user_id     UUID REFERENCES users(id) ON DELETE SET NULL,
    email       TEXT,
    ip_address  TEXT,
    user_agent  TEXT,
    metadata    JSONB,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_log_created_at ON audit_log (created_at);
CREATE INDEX idx_audit_log_event_type ON audit_log (event_type);
CREATE INDEX idx_audit_log_user_id ON audit_log (user_id) WHERE user_id IS NOT NULL;

-- +migrate Down
DROP TABLE audit_log;
