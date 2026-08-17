// refresh_token.go defines the refresh token model for session management.
//
// Refresh tokens enable the "remember me" functionality by allowing users
// to obtain new access tokens without re-authenticating. Tokens store the
// client's IP (as resolved by the API gateway) and user agent; the IP is a
// soft anomaly signal (logged on mismatch, never gating refresh) while the
// user agent is verified when present.

package model

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
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
	Token      string    // Secure random token value (64 bytes) — plaintext, client-facing only, never persisted
	TokenHash  string    // SHA-256 hex digest of Token — this is what's persisted/looked up in the DB
	UserId     string    // UUID of the token owner
	JwtID      string    // UUID of the associated JWT access token
	ValidUntil time.Time // Token expiration time
	Revoked    bool      // Whether the token has been revoked
	Ip         string    // Client IP address at creation time
	UserAgent  string    // Client user agent at creation time
}

// HashToken returns the hex-encoded SHA-256 digest of a refresh token's
// plaintext value. Unsalted SHA-256 is appropriate here because the input
// already carries 256 bits of entropy from GenerateSecureRandomString —
// unlike password hashing, no salt or slow KDF is needed.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
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
		TokenHash:  HashToken(str),
		UserId:     user.ID,
		JwtID:      jwtID,
		ValidUntil: time.Now().Add(ttl),
		Revoked:    false,
		Ip:         FirstIP(ip),
		UserAgent:  userAgent,
	}, nil
}

// FirstIP returns the first non-empty, whitespace-trimmed entry of a
// comma-separated IP chain, or "" if the chain is empty. The client IP is
// always stored as a single IP, never a raw comma-joined X-Forwarded-For
// value, so that matching at refresh time is unambiguous.
func FirstIP(chain string) string {
	for _, part := range strings.Split(chain, ",") {
		if ip := strings.TrimSpace(part); ip != "" {
			return ip
		}
	}
	return ""
}

// Verify checks if the refresh token is still usable for the given client.
// It validates: not revoked, not expired, user agent matches. The IP is
// deliberately NOT gated here — it is a soft anomaly signal, compared by the
// server via MatchesIP and logged on mismatch, never fatal (mobile clients
// legitimately change IP between login and refresh).
func (t RefreshToken) Verify(userAgent string) error {
	if t.Revoked {
		return errors.New("token is revoked")
	}
	if t.ValidUntil.Before(time.Now()) {
		return errors.New("token is expired")
	}
	if t.UserAgent != userAgent {
		return errors.New("user agent does not match")
	}
	return nil
}

// MatchesIP reports whether the token's bound IP appears in the given
// comma-separated IP chain (the X-Forwarded-For style value the gateway
// forwards under x-orig-ip). Tokens stored without an IP — issued on a
// direct/unbound path, or legacy rows — always match. A mismatch is a soft
// signal: the caller should log it, not reject the request.
func (t RefreshToken) MatchesIP(origIp string) bool {
	if t.Ip == "" {
		return true
	}
	for _, part := range strings.Split(origIp, ",") {
		if strings.TrimSpace(part) == t.Ip {
			return true
		}
	}
	return false
}
