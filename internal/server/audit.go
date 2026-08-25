// audit.go implements a non-blocking, asynchronous writer for audit_log
// events, plus thin per-event-type helpers that build a db.AuditEvent from
// handler context (IP/user-agent, subject, actor) and hand it off to the
// writer.
//
// There is no existing async-worker primitive in this codebase to build on
// -- every other background routine is a simple hourly ticker
// (cmd/authservice/main.go's keyChecker/dbMaintenance), and every other DB
// write in this package is synchronous fire-and-forget (see throttle.go).
// AuditWriter keeps the same fail-open philosophy: emit never blocks the
// caller, and a full buffer drops the event (logged) rather than stalling
// the request that triggered it. The actual DB write happens on a
// background drain loop -- see cmd/authservice/main.go's auditFlusher.

package server

import (
	"context"

	"github.com/swayrider/authservice/internal/db"
	"github.com/swayrider/authservice/internal/model"
	log "github.com/swayrider/swlib/logger"
	"github.com/swayrider/swlib/security"
)

// AuditWriter buffers AuditEvents for asynchronous persistence by a drain
// loop (cmd/authservice/main.go's auditFlusher) that owns the database
// connection.
type AuditWriter struct {
	ch chan db.AuditEvent
	lg *log.Logger
}

// NewAuditWriter creates an AuditWriter with the given channel buffer size.
// A bufSize <= 0 still produces a working writer -- emit simply drops more
// eagerly if nothing is draining the channel.
func NewAuditWriter(bufSize int, lgr *log.Logger) *AuditWriter {
	if bufSize < 0 {
		bufSize = 0
	}
	return &AuditWriter{
		ch: make(chan db.AuditEvent, bufSize),
		lg: lgr.Derive(log.WithComponent("AuditWriter")),
	}
}

// Chan exposes the receive side of the buffer for the drain loop to consume.
// Not intended for use outside that loop.
func (w *AuditWriter) Chan() <-chan db.AuditEvent {
	return w.ch
}

// Emit queues ev for asynchronous persistence. Exported for the web layer,
// which shares the same AuditWriter instance; the unexported emit used by the
// per-event helpers below is the same code path.
func (w *AuditWriter) Emit(ev db.AuditEvent) {
	w.emit(ev)
}

// emit queues ev for asynchronous persistence. It never blocks: if the
// buffer is full, the event is dropped and a warning logged rather than
// stalling the request that triggered it.
func (w *AuditWriter) emit(ev db.AuditEvent) {
	select {
	case w.ch <- ev:
	default:
		w.lg.Warnf("audit event dropped (buffer full): %s", ev.EventType)
	}
}

// auditIPUA extracts the caller's IP/user-agent using the same
// security.GetOrigIp/GetUserAgent + model.FirstIP pattern used by every
// other handler in this package.
func auditIPUA(ctx context.Context) (ip, ua string) {
	origIp, _ := security.GetOrigIp(ctx)
	ua, _ = security.GetUserAgent(ctx)
	return model.FirstIP(origIp), ua
}

func strPtr(s string) *string { return &s }

func (s *AuthServer) auditLoginSuccess(ctx context.Context, userID, email string) {
	ip, ua := auditIPUA(ctx)
	s.audit.emit(db.AuditEvent{
		EventType: db.AuditLoginSuccess,
		UserID:    strPtr(userID),
		Email:     email,
		IPAddress: ip,
		UserAgent: ua,
	})
}

func (s *AuthServer) auditLoginFailure(ctx context.Context, email, reason string) {
	ip, ua := auditIPUA(ctx)
	s.audit.emit(db.AuditEvent{
		EventType: db.AuditLoginFailure,
		Email:     email,
		IPAddress: ip,
		UserAgent: ua,
		Metadata:  map[string]any{"reason": reason},
	})
}

func (s *AuthServer) auditLogout(ctx context.Context) {
	ip, ua := auditIPUA(ctx)
	s.audit.emit(db.AuditEvent{
		EventType: db.AuditLogout,
		IPAddress: ip,
		UserAgent: ua,
	})
}

func (s *AuthServer) auditRefreshSuccess(ctx context.Context, userID string) {
	ip, ua := auditIPUA(ctx)
	s.audit.emit(db.AuditEvent{
		EventType: db.AuditRefreshSuccess,
		UserID:    strPtr(userID),
		IPAddress: ip,
		UserAgent: ua,
	})
}

func (s *AuthServer) auditRefreshFailure(ctx context.Context, userID *string, reason string) {
	ip, ua := auditIPUA(ctx)
	s.audit.emit(db.AuditEvent{
		EventType: db.AuditRefreshFailure,
		UserID:    userID,
		IPAddress: ip,
		UserAgent: ua,
		Metadata:  map[string]any{"reason": reason},
	})
}

func (s *AuthServer) auditServiceClientAuth(ctx context.Context, clientID string, success bool, reason string) {
	ip, ua := auditIPUA(ctx)
	metadata := map[string]any{"client_id": clientID}
	if !success {
		metadata["reason"] = reason
	}
	s.audit.emit(db.AuditEvent{
		EventType: db.AuditServiceClientAuth,
		IPAddress: ip,
		UserAgent: ua,
		Metadata:  metadata,
	})
}

func (s *AuthServer) auditRegister(ctx context.Context, userID, email string) {
	ip, ua := auditIPUA(ctx)
	s.audit.emit(db.AuditEvent{
		EventType: db.AuditRegister,
		UserID:    strPtr(userID),
		Email:     email,
		IPAddress: ip,
		UserAgent: ua,
	})
}

func (s *AuthServer) auditVerifyEmail(ctx context.Context, userID string) {
	ip, ua := auditIPUA(ctx)
	s.audit.emit(db.AuditEvent{
		EventType: db.AuditVerifyEmail,
		UserID:    strPtr(userID),
		IPAddress: ip,
		UserAgent: ua,
	})
}

func (s *AuthServer) auditPasswordChange(ctx context.Context, userID, email string) {
	ip, ua := auditIPUA(ctx)
	s.audit.emit(db.AuditEvent{
		EventType: db.AuditPasswordChange,
		UserID:    strPtr(userID),
		Email:     email,
		IPAddress: ip,
		UserAgent: ua,
	})
}

func (s *AuthServer) auditPasswordReset(ctx context.Context, userID, email string) {
	ip, ua := auditIPUA(ctx)
	s.audit.emit(db.AuditEvent{
		EventType: db.AuditPasswordReset,
		UserID:    strPtr(userID),
		Email:     email,
		IPAddress: ip,
		UserAgent: ua,
	})
}

// auditBreachedPasswordRejected records a rejection of a password that
// appeared in a known data breach. userID is nil when the rejection happened
// before account creation (registration); email is always set.
func (s *AuthServer) auditBreachedPasswordRejected(ctx context.Context, userID *string, email string) {
	ip, ua := auditIPUA(ctx)
	s.audit.emit(db.AuditEvent{
		EventType: db.AuditPasswordBreachedRejected,
		UserID:    userID,
		Email:     email,
		IPAddress: ip,
		UserAgent: ua,
	})
}

// auditReusedPasswordRejected records a rejection of a new password that
// matches a recent password of the same account.
func (s *AuthServer) auditReusedPasswordRejected(ctx context.Context, userID *string, email string) {
	ip, ua := auditIPUA(ctx)
	s.audit.emit(db.AuditEvent{
		EventType: db.AuditPasswordReuseRejected,
		UserID:    userID,
		Email:     email,
		IPAddress: ip,
		UserAgent: ua,
	})
}

// auditMFASetupStarted records a user beginning TOTP enrollment (a new
// secret was generated and stored, not yet enabled).
func (s *AuthServer) auditMFASetupStarted(ctx context.Context, userID, email string) {
	ip, ua := auditIPUA(ctx)
	s.audit.emit(db.AuditEvent{
		EventType: db.AuditMFASetupStarted,
		UserID:    strPtr(userID),
		Email:     email,
		IPAddress: ip,
		UserAgent: ua,
	})
}

// auditMFAEnabled records a user completing enrollment (the new secret was
// verified with a valid code and MFA is now active for the account).
func (s *AuthServer) auditMFAEnabled(ctx context.Context, userID, email string) {
	ip, ua := auditIPUA(ctx)
	s.audit.emit(db.AuditEvent{
		EventType: db.AuditMFAEnabled,
		UserID:    strPtr(userID),
		Email:     email,
		IPAddress: ip,
		UserAgent: ua,
	})
}

// auditMFADisabled records a user turning MFA off for their account.
func (s *AuthServer) auditMFADisabled(ctx context.Context, userID, email string) {
	ip, ua := auditIPUA(ctx)
	s.audit.emit(db.AuditEvent{
		EventType: db.AuditMFADisabled,
		UserID:    strPtr(userID),
		Email:     email,
		IPAddress: ip,
		UserAgent: ua,
	})
}

// auditMFAVerified records a completed second-factor verification (tokens
// were issued for a pending login).
func (s *AuthServer) auditMFAVerified(ctx context.Context, userID string) {
	ip, ua := auditIPUA(ctx)
	s.audit.emit(db.AuditEvent{
		EventType: db.AuditMFAVerified,
		UserID:    strPtr(userID),
		IPAddress: ip,
		UserAgent: ua,
	})
}

// auditMFAVerifyFailed records a failed second-factor verification attempt.
// reason is one of "invalid_code", "challenge_expired", "locked". userID is
// nil when the challenge itself could not be resolved (absent/expired token),
// so there is no subject to attribute the attempt to.
func (s *AuthServer) auditMFAVerifyFailed(ctx context.Context, userID *string, reason string) {
	ip, ua := auditIPUA(ctx)
	s.audit.emit(db.AuditEvent{
		EventType: db.AuditMFAVerifyFailed,
		UserID:    userID,
		IPAddress: ip,
		UserAgent: ua,
		Metadata:  map[string]any{"reason": reason},
	})
}

// auditMFABackupCodesGenerated records the issuance (or re-issuance) of a
// fresh backup-code set, which invalidates the previous set.
func (s *AuthServer) auditMFABackupCodesGenerated(ctx context.Context, userID string) {
	ip, ua := auditIPUA(ctx)
	s.audit.emit(db.AuditEvent{
		EventType: db.AuditMFABackupCodesGenerated,
		UserID:    strPtr(userID),
		IPAddress: ip,
		UserAgent: ua,
	})
}

// auditMFAResetRequested records a successful (credentials-verified) request
// to email an MFA reset link. This does not mean the reset was completed --
// see the AuditMFAReset event, emitted by the web confirmation handler
// (internal/web/reset_mfa.go) once the emailed link is actually used.
func (s *AuthServer) auditMFAResetRequested(ctx context.Context, userID, email string) {
	ip, ua := auditIPUA(ctx)
	s.audit.emit(db.AuditEvent{
		EventType: db.AuditMFAResetRequested,
		UserID:    strPtr(userID),
		Email:     email,
		IPAddress: ip,
		UserAgent: ua,
	})
}

// auditAccountLocked records the transition of identifier into lockout
// within scope. For db.ScopeLogin, identifier is a normalized email; for
// db.ScopeGetToken it's a service client ID, which isn't an "email" so it
// only goes into metadata.
func (s *AuthServer) auditAccountLocked(ctx context.Context, scope db.ThrottleScope, identifier string) {
	ip, ua := auditIPUA(ctx)
	ev := db.AuditEvent{
		EventType: db.AuditAccountLocked,
		IPAddress: ip,
		UserAgent: ua,
		Metadata:  map[string]any{"scope": string(scope), "identifier": identifier},
	}
	if scope == db.ScopeLogin {
		ev.Email = identifier
	}
	s.audit.emit(ev)
}

// auditAdminCreate records an admin creating a new admin account. subjectID
// is the newly created admin's user ID; actor is the calling admin (nil if
// unavailable, which should not normally happen since this endpoint requires
// admin auth).
func (s *AuthServer) auditAdminCreate(ctx context.Context, subjectID, subjectEmail string, actor *model.UserInternal) {
	ip, ua := auditIPUA(ctx)
	metadata := map[string]any{}
	if actor != nil {
		metadata["actor_user_id"] = actor.ID
		metadata["actor_email"] = actor.Email
	}
	s.audit.emit(db.AuditEvent{
		EventType: db.AuditAdminCreate,
		UserID:    strPtr(subjectID),
		Email:     subjectEmail,
		IPAddress: ip,
		UserAgent: ua,
		Metadata:  metadata,
	})
}

// auditAdminChangeAccount records an admin changing another user's account
// level. subjectID is the user being modified; actor is the calling admin.
func (s *AuthServer) auditAdminChangeAccount(ctx context.Context, subjectID, newAccountType string, actor *model.UserInternal) {
	ip, ua := auditIPUA(ctx)
	metadata := map[string]any{"new_account_type": newAccountType}
	if actor != nil {
		metadata["actor_user_id"] = actor.ID
		metadata["actor_email"] = actor.Email
	}
	s.audit.emit(db.AuditEvent{
		EventType: db.AuditAdminChangeAccount,
		UserID:    strPtr(subjectID),
		IPAddress: ip,
		UserAgent: ua,
		Metadata:  metadata,
	})
}
