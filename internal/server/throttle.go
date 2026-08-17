package server

import (
	"context"
	"strings"
	"time"

	"github.com/swayrider/authservice/internal/db"
)

// ThrottleConfig bundles the tunables for account lockout (Login/GetToken)
// and email cooldown (Register/VerifyEmail/RequestPasswordReset).
//
// Its zero value disables every check: a zero MaxAttempts/EmailCooldown is
// treated by internal/db.RecordAttemptResult/TryConsumeEmailCooldown as
// "disabled", so callers that don't explicitly configure throttling (e.g.
// existing tests via newTestServer) are unaffected.
type ThrottleConfig struct {
	LoginMaxAttempts      int
	LoginWindow           time.Duration
	LoginLockoutDuration  time.Duration
	ClientMaxAttempts     int
	ClientWindow          time.Duration
	ClientLockoutDuration time.Duration
	EmailCooldown         time.Duration
}

// normalizeIdentifier canonicalizes a user-supplied email for use as a
// throttle key, so "User@Example.com" and " user@example.com " share one
// counter.
func normalizeIdentifier(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// isLocked reports whether identifier is currently locked out within scope.
// It fails open (reports not-locked) on a DB error: a transient DB blip must
// never itself become a denial-of-service or a way to force a false "locked"
// result for a legitimate caller.
func (s *AuthServer) isLocked(ctx context.Context, scope db.ThrottleScope, identifier string) bool {
	locked, err := s.DB().IsAttemptLocked(ctx, scope, identifier)
	if err != nil {
		s.Logger().Warnf("isLocked: %v", err)
		return false
	}
	return locked
}

// recordLoginAttempt records a Login success/failure for the given
// (normalized) email against the configured login lockout thresholds.
func (s *AuthServer) recordLoginAttempt(ctx context.Context, identifier string, success bool) {
	if err := s.DB().RecordAttemptResult(ctx, db.ScopeLogin, identifier, success,
		s.throttle.LoginMaxAttempts, s.throttle.LoginWindow, s.throttle.LoginLockoutDuration); err != nil {
		s.Logger().Warnf("recordLoginAttempt: %v", err)
	}
}

// recordClientAttempt records a GetToken success/failure for the given
// client ID against the configured service-client lockout thresholds.
func (s *AuthServer) recordClientAttempt(ctx context.Context, clientID string, success bool) {
	if err := s.DB().RecordAttemptResult(ctx, db.ScopeGetToken, clientID, success,
		s.throttle.ClientMaxAttempts, s.throttle.ClientWindow, s.throttle.ClientLockoutDuration); err != nil {
		s.Logger().Warnf("recordClientAttempt: %v", err)
	}
}

// tryConsumeEmailCooldown attempts to consume the cooldown budget for
// identifier within scope, failing open (allowing the send) on a DB error --
// a transient DB hiccup should never permanently suppress legitimate mail.
func (s *AuthServer) tryConsumeEmailCooldown(ctx context.Context, scope db.ThrottleScope, identifier string) bool {
	allow, err := s.DB().TryConsumeEmailCooldown(ctx, scope, identifier, s.throttle.EmailCooldown)
	if err != nil {
		s.Logger().Warnf("tryConsumeEmailCooldown: %v", err)
		return true
	}
	return allow
}
