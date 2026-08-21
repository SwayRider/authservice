package server

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/swayrider/authservice/internal/db"
	"github.com/swayrider/authservice/internal/model"
	authv1 "github.com/swayrider/protos/auth/v1"
)

// =============================================================================
// Register breach-rejection audit
// =============================================================================

func TestRegister_BreachedPassword_EmitsAuditEvent(t *testing.T) {
	mdb := &mockDB{}
	srv := newTestServerWithBreached(mdb, &noopMailSender{}, &mockBreachedChecker{
		isBreachedFn: func(_ context.Context, _ string) (bool, int, error) {
			return true, 7, nil
		},
	})
	ctx := context.Background()

	_, err := srv.Register(ctx, &authv1.RegisterRequest{
		Email:    "new@example.com",
		Password: testPassword,
	})
	if err == nil {
		t.Fatal("expected rejection, got nil")
	}

	ev := waitForAuditEvent(t, srv)
	if ev.EventType != db.AuditPasswordBreachedRejected {
		t.Fatalf("EventType = %q, want %q", ev.EventType, db.AuditPasswordBreachedRejected)
	}
	if ev.Email != "new@example.com" {
		t.Errorf("Email = %q, want %q", ev.Email, "new@example.com")
	}
	if ev.UserID != nil {
		t.Errorf("UserID = %v, want nil (no account exists at registration rejection)", *ev.UserID)
	}
}

// =============================================================================
// ChangePassword rejection audits
// =============================================================================

func TestChangePassword_ReusedPassword_EmitsAuditEvent(t *testing.T) {
	mdb := &mockDB{
		getUserByIDFn: func(_ context.Context, _ string) (*model.UserInternal, error) {
			return testUser(), nil
		},
		checkPasswordReuseFn: func(_ context.Context, _, _ string) (bool, error) {
			return true, nil
		},
	}
	srv := newTestServer(mdb, &noopMailSender{})
	ctx := claimsContext("test-user-id")

	_, err := srv.ChangePassword(ctx, &authv1.ChangePasswordRequest{
		OldPassword: testPassword,
		NewPassword: "AnotherStr0ng!Passw0rd",
	})
	if err == nil {
		t.Fatal("expected rejection, got nil")
	}

	ev := waitForAuditEvent(t, srv)
	if ev.EventType != db.AuditPasswordReuseRejected {
		t.Fatalf("EventType = %q, want %q", ev.EventType, db.AuditPasswordReuseRejected)
	}
	if ev.UserID == nil || *ev.UserID != "test-user-id" {
		t.Errorf("UserID = %v, want %q", ev.UserID, "test-user-id")
	}
	if ev.Email != "test@example.com" {
		t.Errorf("Email = %q, want %q", ev.Email, "test@example.com")
	}
}

func TestChangePassword_BreachedPassword_EmitsAuditEvent(t *testing.T) {
	mdb := &mockDB{
		getUserByIDFn: func(_ context.Context, _ string) (*model.UserInternal, error) {
			return testUser(), nil
		},
	}
	srv := newTestServerWithBreached(mdb, &noopMailSender{}, &mockBreachedChecker{
		isBreachedFn: func(_ context.Context, _ string) (bool, int, error) {
			return true, 3, nil
		},
	})
	ctx := claimsContext("test-user-id")

	_, err := srv.ChangePassword(ctx, &authv1.ChangePasswordRequest{
		OldPassword: testPassword,
		NewPassword: "AnotherStr0ng!Passw0rd",
	})
	if err == nil {
		t.Fatal("expected rejection, got nil")
	}

	ev := waitForAuditEvent(t, srv)
	if ev.EventType != db.AuditPasswordBreachedRejected {
		t.Fatalf("EventType = %q, want %q", ev.EventType, db.AuditPasswordBreachedRejected)
	}
	if ev.UserID == nil || *ev.UserID != "test-user-id" {
		t.Errorf("UserID = %v, want %q", ev.UserID, "test-user-id")
	}
}

// =============================================================================
// ResetPassword rejection audits
// =============================================================================

func TestResetPassword_BreachedPassword_EmitsAuditEvent(t *testing.T) {
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
	}
	srv := newTestServerWithBreached(mdb, &noopMailSender{}, &mockBreachedChecker{
		isBreachedFn: func(_ context.Context, _ string) (bool, int, error) {
			return true, 5, nil
		},
	})
	ctx := context.Background()

	_, err := srv.ResetPassword(ctx, &authv1.ResetPasswordRequest{
		UserId:      "test-user-id",
		Token:       "valid-reset-token",
		NewPassword: "AnotherStr0ng!Passw0rd",
	})
	if err == nil {
		t.Fatal("expected rejection, got nil")
	}

	ev := waitForAuditEvent(t, srv)
	if ev.EventType != db.AuditPasswordBreachedRejected {
		t.Fatalf("EventType = %q, want %q", ev.EventType, db.AuditPasswordBreachedRejected)
	}
	if ev.UserID == nil || *ev.UserID != "test-user-id" {
		t.Errorf("UserID = %v, want %q", ev.UserID, "test-user-id")
	}
	if ev.Email != "test@example.com" {
		t.Errorf("Email = %q, want %q", ev.Email, "test@example.com")
	}
}

func TestResetPassword_ReusedPassword_EmitsAuditEvent(t *testing.T) {
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
		checkPasswordReuseFn: func(_ context.Context, _, _ string) (bool, error) {
			return true, nil
		},
	}
	srv := newTestServer(mdb, &noopMailSender{})
	ctx := context.Background()

	_, err := srv.ResetPassword(ctx, &authv1.ResetPasswordRequest{
		UserId:      "test-user-id",
		Token:       "valid-reset-token",
		NewPassword: "AnotherStr0ng!Passw0rd",
	})
	if err == nil {
		t.Fatal("expected rejection, got nil")
	}

	ev := waitForAuditEvent(t, srv)
	if ev.EventType != db.AuditPasswordReuseRejected {
		t.Fatalf("EventType = %q, want %q", ev.EventType, db.AuditPasswordReuseRejected)
	}
	if ev.UserID == nil || *ev.UserID != "test-user-id" {
		t.Errorf("UserID = %v, want %q", ev.UserID, "test-user-id")
	}
}

// =============================================================================
// Fail-open produces no rejection audit event
// =============================================================================

func TestRegister_BreachCheckError_NoRejectionAuditEvent(t *testing.T) {
	mdb := &mockDB{
		registerUserFn: func(_ context.Context, _, _ string) (string, error) {
			return "new-user-id", nil
		},
	}
	srv := newTestServerWithBreached(mdb, &noopMailSender{}, &mockBreachedChecker{
		isBreachedFn: func(_ context.Context, _ string) (bool, int, error) {
			return false, 0, errors.New("hibp is down")
		},
	})
	ctx := context.Background()

	if _, err := srv.Register(ctx, &authv1.RegisterRequest{
		Email:    "new@example.com",
		Password: testPassword,
	}); err != nil {
		t.Fatalf("Register failed: %v (want fail open)", err)
	}

	// The account is created, so the first event is the register event --
	// never a rejection event.
	ev := waitForAuditEvent(t, srv)
	if ev.EventType == db.AuditPasswordBreachedRejected {
		t.Fatalf("unexpected rejection audit event on fail-open: %+v", ev)
	}
}
