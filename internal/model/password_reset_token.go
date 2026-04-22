// password_reset_token.go defines the password reset token model.
//
// Password reset tokens allow users to set a new password without knowing
// their current password. Tokens are short-lived (30 minutes) for security.

package model

import (
	"time"

	"github.com/swayrider/swlib/crypto"
)

const (
	DefaultPasswordResetTokenTTL = 30 * time.Minute
)

// PasswordResetToken represents a password reset token.
type PasswordResetToken struct {
	Token      string    // Secure random token value (64 bytes)
	UserId     string    // UUID of the user requesting reset
	ValidUntil time.Time // Token expiration time (30 minutes from creation)
}

// NewPasswordResetToken creates a new password reset token.
// The token is a 64-byte secure random string.
func NewPasswordResetToken(
	user *User,
	ttl time.Duration,
) (*PasswordResetToken, error) {
	str, err := crypto.GenerateSecureRandomString(64)
	if err != nil {
		return nil, err
	}
	return &PasswordResetToken{
		Token:      str,
		UserId:     user.ID,
		ValidUntil: time.Now().Add(ttl),
	}, nil
}

// IsNotExpired returns true if the token is not expired
func (t PasswordResetToken) IsNotExpired() bool {
	return time.Now().Before(t.ValidUntil)
}

// Verify returns true if the token is valid
func (t PasswordResetToken) Verify(
	userId string,
	token string,
) bool {
	return t.UserId == userId && t.Token == token && t.IsNotExpired()
}
