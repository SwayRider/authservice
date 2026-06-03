package model

import (
	"testing"
	"time"
)

// =============================================================================
// NewPasswordResetToken Tests
// =============================================================================

func TestNewPasswordResetToken(t *testing.T) {
	user := &User{ID: "user-reset-1"}
	ttl := 30 * time.Minute

	before := time.Now()
	tok, err := NewPasswordResetToken(user, ttl)
	after := time.Now()

	if err != nil {
		t.Fatalf("NewPasswordResetToken failed: %v", err)
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

func TestNewPasswordResetToken_UniqueTokens(t *testing.T) {
	user := &User{ID: "user-reset-1"}
	tok1, err := NewPasswordResetToken(user, time.Minute)
	if err != nil {
		t.Fatalf("first NewPasswordResetToken failed: %v", err)
	}
	tok2, err := NewPasswordResetToken(user, time.Minute)
	if err != nil {
		t.Fatalf("second NewPasswordResetToken failed: %v", err)
	}
	if tok1.Token == tok2.Token {
		t.Error("expected unique tokens for each call")
	}
}

// =============================================================================
// PasswordResetToken.IsNotExpired Tests
// =============================================================================

func TestPasswordResetToken_IsNotExpired(t *testing.T) {
	tests := []struct {
		name       string
		validUntil time.Time
		want       bool
	}{
		{"fresh token", time.Now().Add(30 * time.Minute), true},
		{"just expired", time.Now().Add(-time.Millisecond), false},
		{"long expired", time.Now().Add(-time.Hour), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tok := PasswordResetToken{ValidUntil: tt.validUntil}
			if got := tok.IsNotExpired(); got != tt.want {
				t.Errorf("IsNotExpired() = %v, want %v", got, tt.want)
			}
		})
	}
}

// =============================================================================
// PasswordResetToken.Verify Tests
// =============================================================================

func TestPasswordResetToken_Verify(t *testing.T) {
	const userId = "user-abc"
	const token = "resettoken"
	future := time.Now().Add(30 * time.Minute)
	past := time.Now().Add(-time.Minute)

	tests := []struct {
		name       string
		tok        PasswordResetToken
		userId     string
		token      string
		wantResult bool
	}{
		{
			name:       "valid",
			tok:        PasswordResetToken{Token: token, UserId: userId, ValidUntil: future},
			userId:     userId,
			token:      token,
			wantResult: true,
		},
		{
			name:       "expired",
			tok:        PasswordResetToken{Token: token, UserId: userId, ValidUntil: past},
			userId:     userId,
			token:      token,
			wantResult: false,
		},
		{
			name:       "wrong userId",
			tok:        PasswordResetToken{Token: token, UserId: userId, ValidUntil: future},
			userId:     "other-user",
			token:      token,
			wantResult: false,
		},
		{
			name:       "wrong token",
			tok:        PasswordResetToken{Token: token, UserId: userId, ValidUntil: future},
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
