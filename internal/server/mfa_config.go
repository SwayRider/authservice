// mfa_config.go defines the server-side configuration for TOTP two-factor
// authentication. It is built by cmd/authservice/main.go from the MFA_*
// config fields (see PLAN 02) and handed to NewAuthServer, mirroring how
// ThrottleConfig and the BreachedChecker are plumbed in.
//
// The zero value disables MFA: management endpoints fail closed with
// "mfa is disabled" and the login flow skips the second-factor step, so
// callers that don't configure MFA (e.g. existing tests via newTestServer)
// are unaffected.

package server

import (
	"time"

	"github.com/swayrider/swlib/totp"
)

// MFAConfig bundles the tunables for TOTP second-factor authentication:
// the global switch, code/backup-code parameters, and the brute-force
// defenses (per-challenge attempt cap and per-user throttle scope).
type MFAConfig struct {
	Enabled              bool          // MFA_ENABLED; false bypasses MFA in login and fails closed on management
	CodeLength           int           // MFA_CODE_LENGTH — TOTP digits
	TimeStep             time.Duration // MFA_TIME_STEP — seconds per TOTP window
	GracePeriod          int           // MFA_GRACE_PERIOD — accept ±N windows around the current one
	BackupCodeCount      int           // MFA_BACKUP_CODES — backup codes issued per enrollment
	ChallengeTTL         time.Duration // MFA_CHALLENGE_TTL_SECS — pending-login challenge lifetime
	ChallengeMaxAttempts int           // MFA_CHALLENGE_MAX_ATTEMPTS — guesses before a challenge is invalidated
	LockoutMaxAttempts   int           // MFA_LOCKOUT_THRESHOLD — failed verifications before the MFA scope locks
	LockoutWindow        time.Duration // MFA_LOCKOUT_WINDOW_SECS — sliding window for the lockout counter
	LockoutDuration      time.Duration // MFA_LOCKOUT_DURATION_SECS — how long the MFA scope stays locked
}

// totpConfig derives the swlib/totp.Config used for code generation and
// validation from the MFAConfig. SecretSize is left at its zero value so
// swlib/totp applies its default (20 bytes -> 32 base32 chars).
func (c MFAConfig) totpConfig() totp.Config {
	return totp.Config{
		CodeLength:  c.CodeLength,
		TimeStep:    c.TimeStep,
		GracePeriod: c.GracePeriod,
	}
}
