// throttle.go implements defense-in-depth brute-force and spam protection:
//   - account-level lockout after repeated failed attempts (Login, GetToken)
//   - per-identifier cooldown on endpoints that send outbound mail
//
// Both concerns share the security_throttle table, discriminated by scope,
// so a failure/cooldown recorded in one scope never affects another even for
// the same identifier (e.g. the same email address across Login and
// RequestPasswordReset).

package db

import (
	"context"
	"database/sql"
	"time"

	log "github.com/swayrider/swlib/logger"
)

// ThrottleScope identifies an independent throttle counter/cooldown budget.
type ThrottleScope string

const (
	ScopeLogin              ThrottleScope = "login"
	ScopeGetToken           ThrottleScope = "get_token"
	ScopeEmailVerification  ThrottleScope = "email_verification"
	ScopeEmailPasswordReset ThrottleScope = "email_password_reset"
	ScopeEmailSendByIP      ThrottleScope = "email_send_by_ip"
	ScopeMFA                ThrottleScope = "mfa"
	ScopeEmailMFAReset      ThrottleScope = "email_mfa_reset"
)

// IsAttemptLocked reports whether identifier is currently locked out within scope.
func (d *DB) IsAttemptLocked(ctx context.Context, scope ThrottleScope, identifier string) (bool, error) {
	lg := d.lg.Derive(log.WithFunction("IsAttemptLocked"))

	if err := d.checkConnection(); err != nil {
		lg.Warnf("IsAttemptLocked: %v", err)
		return false, err
	}

	var locked bool
	err := d.QueryRowContext(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM security_throttle
			WHERE scope = $1 AND identifier = $2
			  AND locked_until IS NOT NULL AND locked_until > now()
		)
	`, scope, identifier).Scan(&locked)
	if err != nil {
		lg.Warnf("IsAttemptLocked: %v", err)
		return false, err
	}
	return locked, nil
}

// RecordAttemptResult records the outcome of an attempt against scope/identifier.
//
// A success clears any existing failure counter and lock. A failure increments
// the counter -- resetting it first if the sliding window has elapsed since it
// started -- and locks the identifier out for lockoutDuration once the count
// reaches maxAttempts within window.
//
// maxAttempts <= 0 disables lockout for this call entirely (nothing is
// recorded); this is what keeps callers that don't configure a ThrottleConfig
// unaffected.
//
// The returned bool is true only on the call whose failure causes the
// transition into lockout (count first reaching maxAttempts) -- not on every
// subsequent blocked attempt, since those are turned away earlier by
// IsAttemptLocked and never reach here. Callers use this to emit a single
// auth.account_locked audit event per lockout episode rather than one per
// blocked attempt.
func (d *DB) RecordAttemptResult(
	ctx context.Context,
	scope ThrottleScope,
	identifier string,
	success bool,
	maxAttempts int,
	window time.Duration,
	lockoutDuration time.Duration,
) (bool, error) {
	lg := d.lg.Derive(log.WithFunction("RecordAttemptResult"))

	if maxAttempts <= 0 {
		return false, nil
	}

	if err := d.checkConnection(); err != nil {
		lg.Warnf("RecordAttemptResult: %v", err)
		return false, err
	}

	if success {
		_, err := d.ExecContext(ctx, `
			UPDATE security_throttle
			SET attempt_count = 0, locked_until = NULL, window_start = now(), last_attempt_at = now()
			WHERE scope = $1 AND identifier = $2
		`, scope, identifier)
		if err != nil {
			lg.Warnf("RecordAttemptResult: %v", err)
		}
		return false, err
	}

	var count int
	err := d.QueryRowContext(ctx, `
		INSERT INTO security_throttle (scope, identifier, attempt_count, window_start, last_attempt_at)
		VALUES ($1, $2, 1, now(), now())
		ON CONFLICT (scope, identifier) DO UPDATE
		SET attempt_count = CASE
				WHEN security_throttle.window_start < now() - make_interval(secs => $3) THEN 1
				ELSE security_throttle.attempt_count + 1
			END,
			window_start = CASE
				WHEN security_throttle.window_start < now() - make_interval(secs => $3) THEN now()
				ELSE security_throttle.window_start
			END,
			last_attempt_at = now()
		RETURNING attempt_count
	`, scope, identifier, window.Seconds()).Scan(&count)
	if err != nil {
		lg.Warnf("RecordAttemptResult: %v", err)
		return false, err
	}

	if count >= maxAttempts {
		_, err = d.ExecContext(ctx, `
			UPDATE security_throttle
			SET locked_until = now() + make_interval(secs => $3)
			WHERE scope = $1 AND identifier = $2
		`, scope, identifier, lockoutDuration.Seconds())
		if err != nil {
			lg.Warnf("RecordAttemptResult: %v", err)
			return false, err
		}
		// Only the call that hits exactly maxAttempts is the transition into
		// lockout; later blocked attempts never reach RecordAttemptResult at
		// all (IsAttemptLocked turns them away first), so no extra guard is
		// needed here.
		return count == maxAttempts, nil
	}

	return false, nil
}

// TryConsumeEmailCooldown attempts to consume the cooldown budget for
// identifier within scope. It returns true if the caller may proceed (and the
// cooldown timestamp has been updated to now), or false if identifier is
// still within its cooldown window.
//
// cooldown <= 0 disables the cooldown for this call (always allowed).
func (d *DB) TryConsumeEmailCooldown(ctx context.Context, scope ThrottleScope, identifier string, cooldown time.Duration) (bool, error) {
	lg := d.lg.Derive(log.WithFunction("TryConsumeEmailCooldown"))

	if cooldown <= 0 {
		return true, nil
	}

	if err := d.checkConnection(); err != nil {
		lg.Warnf("TryConsumeEmailCooldown: %v", err)
		return false, err
	}

	var t time.Time
	err := d.QueryRowContext(ctx, `
		INSERT INTO security_throttle (scope, identifier, last_attempt_at)
		VALUES ($1, $2, now())
		ON CONFLICT (scope, identifier) DO UPDATE
		SET last_attempt_at = now()
		WHERE security_throttle.last_attempt_at < now() - make_interval(secs => $3)
		RETURNING last_attempt_at
	`, scope, identifier, cooldown.Seconds()).Scan(&t)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		lg.Warnf("TryConsumeEmailCooldown: %v", err)
		return false, err
	}
	return true, nil
}

// cleanupSecurityThrottle deletes throttle rows that are no longer relevant:
// not currently locked and idle for 24h.
func (d *DB) cleanupSecurityThrottle(ctx context.Context) error {
	_, err := d.ExecContext(ctx, `
		DELETE FROM security_throttle
		WHERE last_attempt_at < now() - interval '24 hours'
		  AND (locked_until IS NULL OR locked_until < now())
	`)
	return err
}
