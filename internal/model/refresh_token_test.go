package model

import (
	"testing"
	"time"
)

// =============================================================================
// NewRefreshToken Tests
// =============================================================================

func TestNewRefreshToken(t *testing.T) {
	user := &User{ID: "user-abc"}
	jwtID := "jwt-xyz"
	ip := "192.168.1.1"
	ua := "TestAgent/1.0"
	ttl := 30 * 24 * time.Hour

	before := time.Now()
	tok, err := NewRefreshToken(user, jwtID, ttl, ip, ua)
	after := time.Now()

	if err != nil {
		t.Fatalf("NewRefreshToken failed: %v", err)
	}
	if tok.Token == "" {
		t.Error("expected non-empty token")
	}
	if tok.TokenHash != HashToken(tok.Token) {
		t.Errorf("expected TokenHash to be HashToken(Token), got %q", tok.TokenHash)
	}
	if tok.TokenHash == tok.Token {
		t.Error("expected TokenHash to differ from Token")
	}
	if tok.UserId != user.ID {
		t.Errorf("expected UserId %q, got %q", user.ID, tok.UserId)
	}
	if tok.JwtID != jwtID {
		t.Errorf("expected JwtID %q, got %q", jwtID, tok.JwtID)
	}
	if tok.Ip != ip {
		t.Errorf("expected Ip %q, got %q", ip, tok.Ip)
	}
	if tok.UserAgent != ua {
		t.Errorf("expected UserAgent %q, got %q", ua, tok.UserAgent)
	}
	if tok.Revoked {
		t.Error("new token should not be revoked")
	}
	expectedExpiry := before.Add(ttl)
	if tok.ValidUntil.Before(expectedExpiry) || tok.ValidUntil.After(after.Add(ttl)) {
		t.Errorf("ValidUntil %v not in expected range [%v, %v]", tok.ValidUntil, expectedExpiry, after.Add(ttl))
	}
}

func TestNewRefreshToken_UniqueTokens(t *testing.T) {
	user := &User{ID: "user-abc"}
	tok1, err := NewRefreshToken(user, "jwt1", time.Hour, "1.1.1.1", "ua")
	if err != nil {
		t.Fatalf("first NewRefreshToken failed: %v", err)
	}
	tok2, err := NewRefreshToken(user, "jwt2", time.Hour, "1.1.1.1", "ua")
	if err != nil {
		t.Fatalf("second NewRefreshToken failed: %v", err)
	}
	if tok1.Token == tok2.Token {
		t.Error("expected unique tokens for each call")
	}
}

// =============================================================================
// HashToken Tests
// =============================================================================

func TestHashToken_Deterministic(t *testing.T) {
	const token = "some-refresh-token-value"
	first := HashToken(token)
	second := HashToken(token)
	if first != second {
		t.Errorf("expected HashToken to be deterministic for the same input, got %q and %q", first, second)
	}
}

func TestHashToken_FixedLength(t *testing.T) {
	hash := HashToken("arbitrary-input")
	if len(hash) != 64 {
		t.Errorf("expected 64 hex characters (SHA-256), got %d: %q", len(hash), hash)
	}
}

func TestHashToken_DiffersFromInput(t *testing.T) {
	const token = "plaintext-token"
	if HashToken(token) == token {
		t.Error("expected hash to differ from plaintext input")
	}
}

func TestHashToken_DifferentInputsDifferentHashes(t *testing.T) {
	if HashToken("token-a") == HashToken("token-b") {
		t.Error("expected different inputs to produce different hashes")
	}
}

// =============================================================================
// RefreshToken.Verify Tests
// =============================================================================

func TestRefreshToken_Verify_Valid(t *testing.T) {
	tok := RefreshToken{
		Token:      "sometoken",
		UserId:     "user-1",
		JwtID:      "jwt-1",
		ValidUntil: time.Now().Add(time.Hour),
		Revoked:    false,
		Ip:         "10.0.0.1",
		UserAgent:  "Mozilla/5.0",
	}
	if err := tok.Verify("Mozilla/5.0"); err != nil {
		t.Errorf("expected valid token, got error: %v", err)
	}
}

func TestRefreshToken_Verify_Revoked(t *testing.T) {
	tok := RefreshToken{
		Token:      "sometoken",
		ValidUntil: time.Now().Add(time.Hour),
		Revoked:    true,
		Ip:         "10.0.0.1",
		UserAgent:  "Mozilla/5.0",
	}
	if err := tok.Verify("Mozilla/5.0"); err == nil {
		t.Error("expected error for revoked token, got nil")
	}
}

func TestRefreshToken_Verify_Expired(t *testing.T) {
	tok := RefreshToken{
		Token:      "sometoken",
		ValidUntil: time.Now().Add(-time.Minute),
		Revoked:    false,
		Ip:         "10.0.0.1",
		UserAgent:  "Mozilla/5.0",
	}
	if err := tok.Verify("Mozilla/5.0"); err == nil {
		t.Error("expected error for expired token, got nil")
	}
}

func TestRefreshToken_Verify_IgnoresIP(t *testing.T) {
	// The IP is deliberately NOT part of Verify: it is a soft anomaly signal
	// (MatchesIP) that the server logs but never gates on.
	tok := RefreshToken{
		Token:      "sometoken",
		ValidUntil: time.Now().Add(time.Hour),
		Revoked:    false,
		Ip:         "10.0.0.1",
		UserAgent:  "Mozilla/5.0",
	}
	if err := tok.Verify("Mozilla/5.0"); err != nil {
		t.Errorf("Verify must not fail on the stored IP, got error: %v", err)
	}
}

func TestRefreshToken_Verify_WrongUserAgent(t *testing.T) {
	tok := RefreshToken{
		Token:      "sometoken",
		ValidUntil: time.Now().Add(time.Hour),
		Revoked:    false,
		Ip:         "10.0.0.1",
		UserAgent:  "Mozilla/5.0",
	}
	if err := tok.Verify("curl/7.0"); err == nil {
		t.Error("expected error for wrong user agent, got nil")
	}
}

func TestRefreshToken_MatchesIP(t *testing.T) {
	// The stored IP is the client as bound at login; the incoming value (the
	// gateway-forwarded x-orig-ip chain) may contain multiple comma-separated
	// IPs. MatchesIP must find the stored IP anywhere in that list. It is a
	// soft signal: a mismatch is logged, never fatal.
	tok := RefreshToken{
		Token:      "sometoken",
		ValidUntil: time.Now().Add(time.Hour),
		Revoked:    false,
		Ip:         "10.0.0.1",
		UserAgent:  "Mozilla/5.0",
	}

	tests := []struct {
		name   string
		origIp string
		want   bool
	}{
		{"single IP match", "10.0.0.1", true},
		{"multi-IP chain, match at start", "10.0.0.1, 172.16.0.1, 192.168.0.1", true},
		{"multi-IP chain, match in middle", "172.16.0.1, 10.0.0.1, 192.168.0.1", true},
		{"multi-IP chain, match at end", "172.16.0.1, 192.168.0.1, 10.0.0.1", true},
		{"no-space separators", "172.16.0.1,10.0.0.1,192.168.0.1", true},
		{"multi-IP chain, no match", "172.16.0.1, 192.168.0.2", false},
		{"empty incoming, bound token", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tok.MatchesIP(tt.origIp); got != tt.want {
				t.Errorf("MatchesIP(%q) = %v, want %v", tt.origIp, got, tt.want)
			}
		})
	}
}

func TestRefreshToken_MatchesIP_UnboundTokenAlwaysMatches(t *testing.T) {
	// Tokens stored without an IP (direct/unbound path, legacy rows) never
	// produce a mismatch signal.
	tok := RefreshToken{
		Token:      "sometoken",
		ValidUntil: time.Now().Add(time.Hour),
		Ip:         "",
	}
	if !tok.MatchesIP("") {
		t.Error("unbound token with empty incoming should match")
	}
	if !tok.MatchesIP("10.0.0.9") {
		t.Error("unbound token with any incoming should match")
	}
}

func TestNewRefreshToken_NormalizesIP(t *testing.T) {
	user := &User{ID: "user-abc"}

	tok, err := NewRefreshToken(user, "jwt1", time.Hour, "10.0.0.1, 172.16.0.1", "ua")
	if err != nil {
		t.Fatalf("NewRefreshToken failed: %v", err)
	}
	if tok.Ip != "10.0.0.1" {
		t.Errorf("expected stored IP to be the first chain entry, got %q", tok.Ip)
	}

	tok2, err := NewRefreshToken(user, "jwt2", time.Hour, "  10.0.0.2 ,172.16.0.2", "ua")
	if err != nil {
		t.Fatalf("NewRefreshToken failed: %v", err)
	}
	if tok2.Ip != "10.0.0.2" {
		t.Errorf("expected stored IP to be trimmed first entry, got %q", tok2.Ip)
	}

	tok3, err := NewRefreshToken(user, "jwt3", time.Hour, "", "ua")
	if err != nil {
		t.Fatalf("NewRefreshToken failed: %v", err)
	}
	if tok3.Ip != "" {
		t.Errorf("expected empty IP when chain is empty, got %q", tok3.Ip)
	}
}
