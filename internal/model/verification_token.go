// verification_token.go defines the email verification token model.
//
// Verification tokens are sent to users after registration to confirm
// their email address. Tokens are valid for 24 hours by default.

package model

import (
	"time"

	"github.com/swayrider/swlib/crypto"
)

const (
	DefaultVerificationTokenTTL = 24 * time.Hour
)

// VerificationToken represents an email verification token.
type VerificationToken struct {
	Token      string    // Secure random token value (64 bytes)
	UserId     string    // UUID of the user to verify
	ValidUntil time.Time // Token expiration time
}

// NewVerificationToken creates a new verification token
//
// A verification token is generated via a secure random string and a TTL
func NewVerificationToken(
	user *User,
	ttl time.Duration,
) (*VerificationToken, error) {
	str, err := crypto.GenerateSecureRandomString(64)
	if err != nil {
		return nil, err
	}
	return &VerificationToken{
		Token:      str,
		UserId:     user.ID,
		ValidUntil: time.Now().Add(ttl),
	}, nil
}

// IsNotExpired returns true if the token is not expired
func (t VerificationToken) IsNotExpired() bool {
	return time.Now().Before(t.ValidUntil)
}

// Verify returns true if the token is valid
func (t VerificationToken) Verify(
	userId string,
	token string,
) bool {
	return t.UserId == userId && t.Token == token && t.IsNotExpired()
}
