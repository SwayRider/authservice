// mfa_challenge.go defines the pending-login MFA challenge token model.
//
// When a user with MFA enabled logs in with a correct password, the login
// is held open with a short-lived challenge token. The client must then
// present a valid TOTP code or single-use backup code before tokens are
// issued. The raw token is never stored -- only its SHA-256 hash, mirroring
// the refresh-token and password-reset-token patterns.

package model

import "time"

// MFAChallenge represents a pending-login MFA challenge row.
type MFAChallenge struct {
	UserID     string    // UUID of the user awaiting the second factor
	TokenHash  string    // SHA-256 of the challenge token presented by the client
	Attempts   int       // TOTP/backup-code guesses so far against this challenge
	ValidUntil time.Time // Challenge expiry; login must complete before this
}
