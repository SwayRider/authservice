// refresh_token.go defines the refresh token model for session management.
//
// Refresh tokens enable the "remember me" functionality by allowing users
// to obtain new access tokens without re-authenticating. Tokens are bound
// to the client's IP and user agent for security.

package model

import (
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/swayrider/swlib/crypto"
)

const (
	// Refresh token is 30 days valid. To allow for "Remember-me" checkbox
	DefaultRefreshTokenTTL = 30 * 24 * time.Hour
)

// RefreshToken represents a refresh token for obtaining new access tokens.
type RefreshToken struct {
	Token      string    // Secure random token value (64 bytes)
	UserId     string    // UUID of the token owner
	JwtID      string    // UUID of the associated JWT access token
	ValidUntil time.Time // Token expiration time
	Revoked    bool      // Whether the token has been revoked
	Ip         string    // Client IP address at creation time
	UserAgent  string    // Client user agent at creation time
}

// NewRefreshToken creates a new refresh token
//
// A refresh token is generated via a secure random string and a TTL
func NewRefreshToken(
	user *User,
	jwtID string,
	ttl time.Duration,
	ip, userAgent string,
) (*RefreshToken, error) {
	str, err := crypto.GenerateSecureRandomString(64)
	if err != nil {
		return nil, err
	}
	return &RefreshToken{
		Token:      str,
		UserId:     user.ID,
		JwtID:      jwtID,
		ValidUntil: time.Now().Add(ttl),
		Revoked:    false,
		Ip:         ip,
		UserAgent:  userAgent,
	}, nil
}

// Verify checks if the refresh token is valid for the given client.
// It validates: not revoked, not expired, IP matches, user agent matches.
// The IP check supports X-Forwarded-For headers with multiple IPs.
func (t RefreshToken) Verify(origIp, userAgent string) error {
	if t.Revoked {
		return errors.New("token is revoked")
	}
	if t.ValidUntil.Before(time.Now()) {
		return errors.New("token is expired")
	}
	origIps := strings.Split(origIp, ", ")
	if !slices.Contains(origIps, t.Ip) {
		return errors.New("ip does not match")
	}
	if t.UserAgent != userAgent {
		return errors.New("user agent does not match")
	}
	return nil
}
