package model

import (
	"testing"
	"time"
)

// =============================================================================
// NewVerificationToken Tests
// =============================================================================

func TestNewVerificationToken(t *testing.T) {
	user := &User{ID: "user-verify-1"}
	ttl := 24 * time.Hour

	before := time.Now()
	tok, err := NewVerificationToken(user, ttl)
	after := time.Now()

	if err != nil {
		t.Fatalf("NewVerificationToken failed: %v", err)
	}
	if tok.Token == "" {
		t.Error("expected non-empty token")
	}
	if tok.UserId != user.ID {
		t.Errorf("expected UserId %q, got %q", user.ID, tok.UserId)
	}
	expectedExpiry := before.Add(ttl)
	if tok.ValidUntil.Before(expectedExpiry) || tok.ValidUntil.After(after.Add(ttl)) {
		t.Errorf("ValidUntil %v not in expected range [%v, %v]", tok.ValidUntil, expectedExpiry, after.Add(ttl))
	}
}

func TestNewVerificationToken_UniqueTokens(t *testing.T) {
	user := &User{ID: "user-verify-1"}
	tok1, err := NewVerificationToken(user, time.Hour)
	if err != nil {
		t.Fatalf("first NewVerificationToken failed: %v", err)
	}
	tok2, err := NewVerificationToken(user, time.Hour)
	if err != nil {
		t.Fatalf("second NewVerificationToken failed: %v", err)
	}
	if tok1.Token == tok2.Token {
		t.Error("expected unique tokens for each call")
	}
}

// =============================================================================
// VerificationToken.IsNotExpired Tests
// =============================================================================

func TestVerificationToken_IsNotExpired(t *testing.T) {
	tests := []struct {
		name       string
		validUntil time.Time
		want       bool
	}{
		{"fresh token", time.Now().Add(time.Hour), true},
		{"just expired", time.Now().Add(-time.Millisecond), false},
		{"long expired", time.Now().Add(-24 * time.Hour), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tok := VerificationToken{ValidUntil: tt.validUntil}
			if got := tok.IsNotExpired(); got != tt.want {
				t.Errorf("IsNotExpired() = %v, want %v", got, tt.want)
			}
		})
	}
}

// =============================================================================
// VerificationToken.Verify Tests
// =============================================================================

func TestVerificationToken_Verify(t *testing.T) {
	const userId = "user-abc"
	const token = "secrettoken"
	future := time.Now().Add(time.Hour)
	past := time.Now().Add(-time.Minute)

	tests := []struct {
		name       string
		tok        VerificationToken
		userId     string
		token      string
		wantResult bool
	}{
		{
			name:       "valid",
			tok:        VerificationToken{Token: token, UserId: userId, ValidUntil: future},
			userId:     userId,
			token:      token,
			wantResult: true,
		},
		{
			name:       "expired",
			tok:        VerificationToken{Token: token, UserId: userId, ValidUntil: past},
			userId:     userId,
			token:      token,
			wantResult: false,
		},
		{
			name:       "wrong userId",
			tok:        VerificationToken{Token: token, UserId: userId, ValidUntil: future},
			userId:     "other-user",
			token:      token,
			wantResult: false,
		},
		{
			name:       "wrong token",
			tok:        VerificationToken{Token: token, UserId: userId, ValidUntil: future},
			userId:     userId,
			token:      "wrongtoken",
			wantResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.tok.Verify(tt.userId, tt.token)
			if got != tt.wantResult {
				t.Errorf("Verify() = %v, want %v", got, tt.wantResult)
			}
		})
	}
}
