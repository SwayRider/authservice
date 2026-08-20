package server

import (
	"context"
	"testing"
	"time"

	"github.com/swayrider/authservice/internal/db"
	"github.com/swayrider/authservice/internal/model"
	authv1 "github.com/swayrider/protos/auth/v1"
	"github.com/swayrider/swlib/security"
)

// =============================================================================
// RequestPasswordReset email-cooldown Tests
// =============================================================================

func TestRequestPasswordReset_CooldownActive_SkipsSend(t *testing.T) {
	mdb := &mockDB{
		tryConsumeEmailCooldownFn: func(_ context.Context, _ db.ThrottleScope, _ string, _ time.Duration) (bool, error) {
			return false, nil
		},
	}
	mail := newRecordingMailSender()
	srv := newTestServerWithThrottle(mdb, mail, testThrottleConfig())
	ctx := context.Background()

	resp, err := srv.RequestPasswordReset(ctx, &authv1.RequestPasswordResetRequest{Email: "test@example.com"})
	if err != nil {
		t.Fatalf("RequestPasswordReset failed: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	mail.assertNoSend(t)
}

func TestRequestPasswordReset_CooldownElapsed_Sends(t *testing.T) {
	mdb := &mockDB{
		getUserByEmailFn: func(_ context.Context, _ string) (*model.UserInternal, error) {
			return testUser(), nil
		},
		createResetPassTokenFn: func(_ context.Context, _ *model.User) (*model.PasswordResetToken, error) {
			return &model.PasswordResetToken{Token: "test-reset-token"}, nil
		},
	}
	mail := newRecordingMailSender()
	srv := newTestServerWithThrottle(mdb, mail, testThrottleConfig())
	ctx := context.Background()

	if _, err := srv.RequestPasswordReset(ctx, &authv1.RequestPasswordResetRequest{Email: "test@example.com"}); err != nil {
		t.Fatalf("RequestPasswordReset failed: %v", err)
	}
	mail.waitForSend(t)
}

func TestRequestPasswordReset_UsesEmailPasswordResetScope(t *testing.T) {
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

	if _, err := srv.RequestPasswordReset(ctx, &authv1.RequestPasswordResetRequest{Email: "Test@Example.com"}); err != nil {
		t.Fatalf("RequestPasswordReset failed: %v", err)
	}
	// Deliberately a different scope from Register/VerifyEmail's
	// db.ScopeEmailVerification -- password-reset spam and verification
	// spam should not share one budget.
	if gotScope != db.ScopeEmailPasswordReset {
		t.Errorf("scope = %v, want %v", gotScope, db.ScopeEmailPasswordReset)
	}
	if gotIdentifier != "test@example.com" {
		t.Errorf("identifier = %q, want normalized %q", gotIdentifier, "test@example.com")
	}
}

// =============================================================================
// RequestPasswordReset per-IP email-send throttle Tests
// =============================================================================

func TestRequestPasswordReset_IPLocked_SkipsSend(t *testing.T) {
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

	resp, err := srv.RequestPasswordReset(ctx, &authv1.RequestPasswordResetRequest{Email: "test@example.com"})
	if err != nil {
		t.Fatalf("RequestPasswordReset failed: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	mail.assertNoSend(t)
}

func TestRequestPasswordReset_UsesEmailSendByIPScope(t *testing.T) {
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

	if _, err := srv.RequestPasswordReset(ctx, &authv1.RequestPasswordResetRequest{Email: "test@example.com"}); err != nil {
		t.Fatalf("RequestPasswordReset failed: %v", err)
	}
	if gotScope != db.ScopeEmailSendByIP {
		t.Errorf("scope = %v, want %v", gotScope, db.ScopeEmailSendByIP)
	}
	if gotIdentifier != "10.0.0.1" {
		t.Errorf("identifier = %q, want %q", gotIdentifier, "10.0.0.1")
	}
}

func TestResetPassword_RevokesRefreshTokensOnSuccess(t *testing.T) {
	var revokedUserID string
	mdb := &mockDB{
		getUserByIDFn: func(_ context.Context, _ string) (*model.UserInternal, error) {
			return testUser(), nil
		},
		getResetPassTokenFn: func(_ context.Context, _ *model.User) (*model.PasswordResetToken, error) {
			return &model.PasswordResetToken{
				Token:      "valid-reset-token",
				UserId:     "test-user-id",
				ValidUntil: time.Now().Add(time.Hour),
			}, nil
		},
		deleteRefreshTokensByUserIDFn: func(_ context.Context, userId string) error {
			revokedUserID = userId
			return nil
		},
	}
	srv := newTestServer(mdb, &noopMailSender{})
	ctx := context.Background()

	_, err := srv.ResetPassword(ctx, &authv1.ResetPasswordRequest{
		UserId:      "test-user-id",
		Token:       "valid-reset-token",
		NewPassword: "AnotherStr0ng!Passw0rd",
	})
	if err != nil {
		t.Fatalf("ResetPassword failed: %v", err)
	}
	if revokedUserID != "test-user-id" {
		t.Errorf("DeleteRefreshTokensByUserID called with %q, want %q", revokedUserID, "test-user-id")
	}
}

func TestResetPassword_DoesNotRevokeOnInvalidToken(t *testing.T) {
	revokeCalled := false
	mdb := &mockDB{
		getUserByIDFn: func(_ context.Context, _ string) (*model.UserInternal, error) {
			return testUser(), nil
		},
		getResetPassTokenFn: func(_ context.Context, _ *model.User) (*model.PasswordResetToken, error) {
			return &model.PasswordResetToken{
				Token:      "valid-reset-token",
				UserId:     "test-user-id",
				ValidUntil: time.Now().Add(time.Hour),
			}, nil
		},
		deleteRefreshTokensByUserIDFn: func(_ context.Context, _ string) error {
			revokeCalled = true
			return nil
		},
	}
	srv := newTestServer(mdb, &noopMailSender{})
	ctx := context.Background()

	_, err := srv.ResetPassword(ctx, &authv1.ResetPasswordRequest{
		UserId:      "test-user-id",
		Token:       "wrong-token",
		NewPassword: "AnotherStr0ng!Passw0rd",
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if revokeCalled {
		t.Error("DeleteRefreshTokensByUserID should not be called when reset token is invalid")
	}
}
