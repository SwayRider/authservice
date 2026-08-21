package server

import (
	"context"
	"testing"
	"time"

	"github.com/swayrider/authservice/internal/db"
	"github.com/swayrider/authservice/internal/model"
	authv1 "github.com/swayrider/protos/auth/v1"
	log "github.com/swayrider/swlib/logger"
	"github.com/swayrider/swlib/security"
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
	// UserId is never echoed back -- see TestRegister_DuplicateEmail... below
	// for why (anti-enumeration: the response must be identical whether or
	// not an account was actually created).
	if resp.UserId != "" {
		t.Errorf("UserId = %q, want empty", resp.UserId)
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
// Register per-IP email-send throttle Tests
// =============================================================================

func TestRegister_IPLocked_StillCreatesAccountButSkipsSend(t *testing.T) {
	registerCalled := false
	mdb := &mockDB{
		isAttemptLockedFn: func(_ context.Context, scope db.ThrottleScope, identifier string) (bool, error) {
			if scope != db.ScopeEmailSendByIP || identifier != "10.0.0.1" {
				t.Errorf("unexpected scope/identifier: %v/%s", scope, identifier)
			}
			return true, nil
		},
		registerUserFn: func(_ context.Context, _, _ string) (string, error) {
			registerCalled = true
			return "new-user-id", nil
		},
	}
	mail := newRecordingMailSender()
	srv := newTestServerWithThrottle(mdb, mail, testThrottleConfig())
	ctx := context.WithValue(context.Background(), security.OrigIpKey, "10.0.0.1")

	resp, err := srv.Register(ctx, &authv1.RegisterRequest{
		Email:    "new@example.com",
		Password: testPassword,
	})
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}
	if resp.UserId != "" {
		t.Errorf("UserId = %q, want empty", resp.UserId)
	}
	if !registerCalled {
		t.Error("expected RegisterUser to be called even when the caller IP is locked out")
	}
	mail.assertNoSend(t)
}

func TestRegister_UsesEmailSendByIPScope(t *testing.T) {
	var gotScope db.ThrottleScope
	var gotIdentifier string
	mdb := &mockDB{
		registerUserFn: func(_ context.Context, _, _ string) (string, error) {
			return "new-user-id", nil
		},
		recordAttemptResultFn: func(_ context.Context, scope db.ThrottleScope, identifier string, success bool, _ int, _, _ time.Duration) (bool, error) {
			gotScope = scope
			gotIdentifier = identifier
			if success {
				t.Error("expected the per-IP attempt to be recorded as a failure-shaped increment")
			}
			return false, nil
		},
	}
	srv := newTestServerWithThrottle(mdb, &noopMailSender{}, testThrottleConfig())
	ctx := context.WithValue(context.Background(), security.OrigIpKey, "10.0.0.1")

	if _, err := srv.Register(ctx, &authv1.RegisterRequest{
		Email:    "new@example.com",
		Password: testPassword,
	}); err != nil {
		t.Fatalf("Register failed: %v", err)
	}
	if gotScope != db.ScopeEmailSendByIP {
		t.Errorf("scope = %v, want %v", gotScope, db.ScopeEmailSendByIP)
	}
	if gotIdentifier != "10.0.0.1" {
		t.Errorf("identifier = %q, want %q", gotIdentifier, "10.0.0.1")
	}
}

// =============================================================================
// Register enumeration Tests
// =============================================================================

func TestRegister_NewEmail_Succeeds(t *testing.T) {
	mdb := &mockDB{
		registerUserFn: func(_ context.Context, _, _ string) (string, error) {
			return "new-user-id", nil
		},
	}
	srv := newTestServer(mdb, &noopMailSender{})
	ctx := context.Background()

	resp, err := srv.Register(ctx, &authv1.RegisterRequest{
		Email:    "new@example.com",
		Password: testPassword,
	})
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}
	if resp.UserId != "" {
		t.Errorf("UserId = %q, want empty", resp.UserId)
	}
	if resp.Message == "" {
		t.Error("expected a non-empty generic message")
	}
}

func TestRegister_DuplicateEmail_ReturnsGenericResponseAndNotifiesOwner(t *testing.T) {
	// Regression test for enumeration fix: registering an already-used email
	// must return the exact same response shape as a genuinely new
	// registration, and must notify the real owner via a password-reset
	// email rather than telling the caller the account exists.
	mdb := &mockDB{
		registerUserFn: func(_ context.Context, _, _ string) (string, error) {
			return "", db.ErrUniqueViolation
		},
		getUserByEmailFn: func(_ context.Context, email string) (*model.UserInternal, error) {
			u := testUser()
			u.Email = email
			return u, nil
		},
		createResetPassTokenFn: func(_ context.Context, _ *model.User) (*model.PasswordResetToken, error) {
			return &model.PasswordResetToken{Token: "test-reset-token"}, nil
		},
	}
	mail := newRecordingMailSender()
	srv := newTestServer(mdb, mail)
	ctx := context.Background()

	resp, err := srv.Register(ctx, &authv1.RegisterRequest{
		Email:    "existing@example.com",
		Password: testPassword,
	})
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}
	if resp.UserId != "" {
		t.Errorf("UserId = %q, want empty", resp.UserId)
	}
	const wantMsg = "If this email is eligible for registration, check your inbox to continue."
	if resp.Message != wantMsg {
		t.Errorf("Message = %q, want %q", resp.Message, wantMsg)
	}
	mail.waitForSend(t)
}

func TestRegister_InviteOnly_NotInvited_ReturnsGenericResponseWithoutCreatingUser(t *testing.T) {
	registerCalled := false
	mdb := &mockDB{
		isEmailInvitedFn: func(_ context.Context, _ string) (bool, error) {
			return false, nil
		},
		registerUserFn: func(_ context.Context, _, _ string) (string, error) {
			registerCalled = true
			return "new-user-id", nil
		},
	}
	srv := NewAuthServer(mdb, log.New(), &noopMailSender{}, "from@example.com",
		registrationModeInviteOnly, "", "", "", ThrottleConfig{}, MFAConfig{}, NewAuditWriter(10, log.New()), nil)
	ctx := context.Background()

	resp, err := srv.Register(ctx, &authv1.RegisterRequest{
		Email:    "uninvited@example.com",
		Password: testPassword,
	})
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}
	if resp.UserId != "" {
		t.Errorf("UserId = %q, want empty", resp.UserId)
	}
	const wantMsg = "If this email is eligible for registration, check your inbox to continue."
	if resp.Message != wantMsg {
		t.Errorf("Message = %q, want %q (must match the duplicate-email case)", resp.Message, wantMsg)
	}
	if registerCalled {
		t.Error("RegisterUser must not be called for a non-invited email")
	}
}

func TestRegister_InviteOnly_Invited_Succeeds(t *testing.T) {
	consumeInviteCalled := false
	mdb := &mockDB{
		isEmailInvitedFn: func(_ context.Context, _ string) (bool, error) {
			return true, nil
		},
		registerUserFn: func(_ context.Context, _, _ string) (string, error) {
			return "new-user-id", nil
		},
		consumeInviteFn: func(_ context.Context, _ string) error {
			consumeInviteCalled = true
			return nil
		},
	}
	srv := NewAuthServer(mdb, log.New(), &noopMailSender{}, "from@example.com",
		registrationModeInviteOnly, "", "", "", ThrottleConfig{}, MFAConfig{}, NewAuditWriter(10, log.New()), nil)
	ctx := context.Background()

	resp, err := srv.Register(ctx, &authv1.RegisterRequest{
		Email:    "invited@example.com",
		Password: testPassword,
	})
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}
	if resp.UserId != "" {
		t.Errorf("UserId = %q, want empty", resp.UserId)
	}
	if !consumeInviteCalled {
		t.Error("expected ConsumeInvite to be called after a successful invite-only registration")
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

func TestVerifyEmail_IPLocked_SkipsSend(t *testing.T) {
	mdb := &mockDB{
		isAttemptLockedFn: func(_ context.Context, scope db.ThrottleScope, identifier string) (bool, error) {
			if scope != db.ScopeEmailSendByIP || identifier != "10.0.0.1" {
				t.Errorf("unexpected scope/identifier: %v/%s", scope, identifier)
			}
			return true, nil
		},
	}
	mail := newRecordingMailSender()
	srv := newTestServerWithThrottle(mdb, mail, testThrottleConfig())
	ctx := context.WithValue(context.Background(), security.OrigIpKey, "10.0.0.1")

	resp, err := srv.VerifyEmail(ctx, &authv1.VerifyEmailRequest{Email: "test@example.com"})
	if err != nil {
		t.Fatalf("VerifyEmail failed: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	mail.assertNoSend(t)
}

func TestVerifyEmail_UsesEmailSendByIPScope(t *testing.T) {
	var gotScope db.ThrottleScope
	var gotIdentifier string
	mdb := &mockDB{
		recordAttemptResultFn: func(_ context.Context, scope db.ThrottleScope, identifier string, _ bool, _ int, _, _ time.Duration) (bool, error) {
			gotScope = scope
			gotIdentifier = identifier
			return false, nil
		},
	}
	srv := newTestServerWithThrottle(mdb, &noopMailSender{}, testThrottleConfig())
	ctx := context.WithValue(context.Background(), security.OrigIpKey, "10.0.0.1")

	if _, err := srv.VerifyEmail(ctx, &authv1.VerifyEmailRequest{Email: "test@example.com"}); err != nil {
		t.Fatalf("VerifyEmail failed: %v", err)
	}
	if gotScope != db.ScopeEmailSendByIP {
		t.Errorf("scope = %v, want %v", gotScope, db.ScopeEmailSendByIP)
	}
	if gotIdentifier != "10.0.0.1" {
		t.Errorf("identifier = %q, want %q", gotIdentifier, "10.0.0.1")
	}
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
