// audit.go implements the audit_log accessor: a record of security-relevant
// authentication events (login, logout, password changes, admin actions,
// etc.) for incident investigation and audit trail purposes.
//
// Writes are expected to come from internal/server.AuditWriter's async drain
// loop rather than directly from request handlers -- see that package for
// the non-blocking emit path. InsertAuditEvent itself is a plain synchronous
// insert; it has no opinion about who calls it or when.

package db

import (
	"context"
	"encoding/json"

	log "github.com/swayrider/swlib/logger"
)

// AuditEventType identifies the kind of security event an audit_log row
// records.
type AuditEventType string

const (
	AuditLoginSuccess             AuditEventType = "auth.login.success"
	AuditLoginFailure             AuditEventType = "auth.login.failure"
	AuditLogout                   AuditEventType = "auth.logout"
	AuditRefreshSuccess           AuditEventType = "auth.refresh.success"
	AuditRefreshFailure           AuditEventType = "auth.refresh.failure"
	AuditServiceClientAuth        AuditEventType = "auth.service_client.auth"
	AuditRegister                 AuditEventType = "auth.register"
	AuditVerifyEmail              AuditEventType = "auth.verify_email"
	AuditPasswordChange           AuditEventType = "auth.password_change"
	AuditPasswordReset            AuditEventType = "auth.password_reset"
	AuditPasswordBreachedRejected AuditEventType = "auth.password_breached_rejected"
	AuditPasswordReuseRejected    AuditEventType = "auth.password_reuse_rejected"
	AuditAccountLocked            AuditEventType = "auth.account_locked"
	AuditAdminCreate              AuditEventType = "auth.admin.create"
	AuditAdminChangeAccount       AuditEventType = "auth.admin.change_account"
	AuditMFASetupStarted          AuditEventType = "auth.mfa_setup_started"
	AuditMFAEnabled               AuditEventType = "auth.mfa_enabled"
	AuditMFADisabled              AuditEventType = "auth.mfa_disabled"
	AuditMFAVerified              AuditEventType = "auth.mfa_verified"
	AuditMFAVerifyFailed          AuditEventType = "auth.mfa_verify_failed"
	AuditMFABackupCodesGenerated  AuditEventType = "auth.mfa_backup_codes_generated"
)

// AuditEvent is a single row to be written to audit_log. UserID identifies
// the subject of the event (e.g. the account that logged in, or the account
// whose type was changed) -- for admin-initiated events where the actor
// differs from the subject, put the actor's identity in Metadata (e.g.
// "actor_user_id", "actor_email") rather than in UserID.
type AuditEvent struct {
	EventType AuditEventType
	UserID    *string
	Email     string
	IPAddress string
	UserAgent string
	Metadata  map[string]any
}

// InsertAuditEvent writes a single audit_log row.
func (d *DB) InsertAuditEvent(ctx context.Context, ev AuditEvent) error {
	lg := d.lg.Derive(log.WithFunction("InsertAuditEvent"))

	if err := d.checkConnection(); err != nil {
		lg.Warnf("InsertAuditEvent: %v", err)
		return err
	}

	var metadataJSON []byte
	if len(ev.Metadata) > 0 {
		var err error
		metadataJSON, err = json.Marshal(ev.Metadata)
		if err != nil {
			lg.Warnf("InsertAuditEvent: failed to marshal metadata: %v", err)
			return err
		}
	}

	_, err := d.ExecContext(ctx, `
		INSERT INTO audit_log (event_type, user_id, email, ip_address, user_agent, metadata)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, ev.EventType, ev.UserID, ev.Email, ev.IPAddress, ev.UserAgent, metadataJSON)
	if err != nil {
		lg.Warnf("InsertAuditEvent: %v", err)
		return err
	}
	return nil
}

// cleanupAuditLog deletes audit_log rows older than retentionDays.
func (d *DB) cleanupAuditLog(ctx context.Context, retentionDays int) error {
	_, err := d.ExecContext(ctx, `
		DELETE FROM audit_log
		WHERE created_at < now() - make_interval(days => $1)
	`, retentionDays)
	return err
}
