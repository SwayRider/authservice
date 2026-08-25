// mfa_reset_token.go defines the email-verified MFA/TOTP reset token model.
//
// An MFA reset token pairs a random, emailed token with a freshly generated
// (not-yet-active) TOTP secret. Confirming the emailed link with a valid code
// for that secret is what replaces the user's active user_mfa secret -- see
// internal/db/mfa_reset.go and internal/web/reset_mfa.go. Tokens are
// short-lived (30 minutes by default) for the same reason password reset
// tokens are.

package model

import (
	"time"

	"github.com/swayrider/swlib/crypto"
)

const (
	DefaultMFAResetTokenTTL = 30 * time.Minute
)

// MFAResetToken represents a pending MFA reset request.
type MFAResetToken struct {
	Token            string    // Secure random token value (64 bytes)
	UserId           string    // UUID of the user requesting the reset
	PendingSecret    string    // Plaintext TOTP secret awaiting confirmation
	ValidUntil       time.Time // Token expiration time (30 minutes from creation)
	PasswordVerified bool      // Whether the account password has been re-verified on the web confirmation page
	Attempts         int       // Failed password attempts against this token
}

// NewMFAResetToken creates a new MFA reset token for the given pending
// secret. The token is a 64-byte secure random string.
func NewMFAResetToken(
	userId string,
	pendingSecret string,
	ttl time.Duration,
) (*MFAResetToken, error) {
	str, err := crypto.GenerateSecureRandomString(64)
	if err != nil {
		return nil, err
	}
	return &MFAResetToken{
		Token:         str,
		UserId:        userId,
		PendingSecret: pendingSecret,
		ValidUntil:    time.Now().Add(ttl),
	}, nil
}

// IsNotExpired returns true if the token is not expired.
func (t MFAResetToken) IsNotExpired() bool {
	return time.Now().Before(t.ValidUntil)
}

// Verify returns true if the token is valid.
func (t MFAResetToken) Verify(userId string, token string) bool {
	return t.UserId == userId && t.Token == token && t.IsNotExpired()
}
