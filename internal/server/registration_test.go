package server

import (
	"context"
	"testing"
	"time"

	"github.com/swayrider/authservice/internal/db"
	"github.com/swayrider/authservice/internal/model"
	authv1 "github.com/swayrider/protos/auth/v1"
)

// =============================================================================
// Register email-cooldown Tests
// =============================================================================

func TestRegister_CooldownActive_StillCreatesAccountButSkipsSend(t *testing.T) {
	registerCalled := false
	mdb := &mockDB{
		registerUserFn: func(_ context.Context, _, _ string) (string, error) {
			registerCalled = true
			return "new-user-id", nil
		},
		tryConsumeEmailCooldownFn: func(_ context.Context, _ db.ThrottleScope, _ string, _ time.Duration) (bool, error) {
			return false, nil
		},
	}
	mail := newRecordingMailSender()
	srv := newTestServerWithThrottle(mdb, mail, testThrottleConfig())
	ctx := context.Background()

	resp, err := srv.Register(ctx, &authv1.RegisterRequest{
		Email:    "new@example.com",
		Password: testPassword,
	})
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}
	if resp.UserId != "new-user-id" {
		t.Errorf("UserId = %q, want %q", resp.UserId, "new-user-id")
	}
	if !registerCalled {
		t.Error("expected RegisterUser to be called even when cooldown suppresses the email")
	}
	mail.assertNoSend(t)
}

func TestRegister_CooldownElapsed_Sends(t *testing.T) {
	mdb := &mockDB{
		registerUserFn: func(_ context.Context, _, _ string) (string, error) {
			return "new-user-id", nil
		},
		getUserByIDFn: func(_ context.Context, id string) (*model.UserInternal, error) {
			u := testUser()
			u.ID = id
			return u, nil
		},
		createVerificationTokenFn: func(_ context.Context, _ *model.User) (*model.VerificationToken, error) {
			return &model.VerificationToken{Token: "test-verification-token"}, nil
		},
	}
	mail := newRecordingMailSender()
	srv := newTestServerWithThrottle(mdb, mail, testThrottleConfig())
	ctx := context.Background()

	if _, err := srv.Register(ctx, &authv1.RegisterRequest{
		Email:    "new@example.com",
		Password: testPassword,
	}); err != nil {
		t.Fatalf("Register failed: %v", err)
	}
	mail.waitForSend(t)
}

func TestRegister_UsesEmailVerificationScope(t *testing.T) {
	var gotScope db.ThrottleScope
	var gotIdentifier string
	mdb := &mockDB{
		registerUserFn: func(_ context.Context, _, _ string) (string, error) {
			return "new-user-id", nil
		},
		tryConsumeEmailCooldownFn: func(_ context.Context, scope db.ThrottleScope, identifier string, _ time.Duration) (bool, error) {
			gotScope = scope
			gotIdentifier = identifier
			return false, nil
		},
	}
	srv := newTestServerWithThrottle(mdb, &noopMailSender{}, testThrottleConfig())
	ctx := context.Background()

	if _, err := srv.Register(ctx, &authv1.RegisterRequest{
		Email:    "New@Example.com",
		Password: testPassword,
	}); err != nil {
		t.Fatalf("Register failed: %v", err)
	}
	if gotScope != db.ScopeEmailVerification {
		t.Errorf("scope = %v, want %v", gotScope, db.ScopeEmailVerification)
	}
	if gotIdentifier != "new@example.com" {
		t.Errorf("identifier = %q, want normalized %q", gotIdentifier, "new@example.com")
	}
}

// =============================================================================
// VerifyEmail email-cooldown Tests
// =============================================================================

func TestVerifyEmail_CooldownActive_SkipsSend(t *testing.T) {
	mdb := &mockDB{
		tryConsumeEmailCooldownFn: func(_ context.Context, _ db.ThrottleScope, _ string, _ time.Duration) (bool, error) {
			return false, nil
		},
	}
	mail := newRecordingMailSender()
	srv := newTestServerWithThrottle(mdb, mail, testThrottleConfig())
	ctx := context.Background()

	resp, err := srv.VerifyEmail(ctx, &authv1.VerifyEmailRequest{Email: "test@example.com"})
	if err != nil {
		t.Fatalf("VerifyEmail failed: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	mail.assertNoSend(t)
}

func TestVerifyEmail_CooldownElapsed_Sends(t *testing.T) {
	mdb := &mockDB{
		getUserByEmailFn: func(_ context.Context, _ string) (*model.UserInternal, error) {
			return testUser(), nil
		},
		createVerificationTokenFn: func(_ context.Context, _ *model.User) (*model.VerificationToken, error) {
			return &model.VerificationToken{Token: "test-verification-token"}, nil
		},
	}
	mail := newRecordingMailSender()
	srv := newTestServerWithThrottle(mdb, mail, testThrottleConfig())
	ctx := context.Background()

	if _, err := srv.VerifyEmail(ctx, &authv1.VerifyEmailRequest{Email: "test@example.com"}); err != nil {
		t.Fatalf("VerifyEmail failed: %v", err)
	}
	mail.waitForSend(t)
}

func TestVerifyEmail_UsesEmailVerificationScope(t *testing.T) {
	var gotScope db.ThrottleScope
	var gotIdentifier string
	mdb := &mockDB{
		tryConsumeEmailCooldownFn: func(_ context.Context, scope db.ThrottleScope, identifier string, _ time.Duration) (bool, error) {
			gotScope = scope
			gotIdentifier = identifier
			return false, nil
		},
	}
	srv := newTestServerWithThrottle(mdb, &noopMailSender{}, testThrottleConfig())
	ctx := context.Background()

	if _, err := srv.VerifyEmail(ctx, &authv1.VerifyEmailRequest{Email: "New@Example.com"}); err != nil {
		t.Fatalf("VerifyEmail failed: %v", err)
	}
	// Must match Register's scope exactly (db.ScopeEmailVerification) --
	// this is what makes the two endpoints share one cooldown budget per
	// address, so an attacker can't reset it by alternating between them.
	if gotScope != db.ScopeEmailVerification {
		t.Errorf("scope = %v, want %v", gotScope, db.ScopeEmailVerification)
	}
	if gotIdentifier != "new@example.com" {
		t.Errorf("identifier = %q, want normalized %q", gotIdentifier, "new@example.com")
	}
}
