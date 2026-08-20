package server

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/swayrider/authservice/internal/model"
	authv1 "github.com/swayrider/protos/auth/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// =============================================================================
// checkNotBreached helper Tests
// =============================================================================

func TestCheckNotBreached_NilChecker_Allows(t *testing.T) {
	srv := newTestServer(&mockDB{}, &noopMailSender{})
	if err := srv.checkNotBreached(context.Background(), "any-password"); err != nil {
		t.Fatalf("checkNotBreached with nil checker = %v, want nil", err)
	}
}

func TestCheckNotBreached_Breached_RejectsWithPrefix(t *testing.T) {
	srv := newTestServerWithBreached(&mockDB{}, &noopMailSender{}, &mockBreachedChecker{
		isBreachedFn: func(_ context.Context, _ string) (bool, int, error) {
			return true, 42, nil
		},
	})

	err := srv.checkNotBreached(context.Background(), "some-password")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("code = %v, want %v", status.Code(err), codes.InvalidArgument)
	}
	// The prefix is the gateway's contract -- keep it stable.
	if msg := status.Convert(err).Message(); !containsPrefix(msg, ErrBreachedPasswordPrefix) {
		t.Errorf("message %q does not start with prefix %q", msg, ErrBreachedPasswordPrefix)
	}
}

func TestCheckNotBreached_CheckerError_FailsOpen(t *testing.T) {
	srv := newTestServerWithBreached(&mockDB{}, &noopMailSender{}, &mockBreachedChecker{
		isBreachedFn: func(_ context.Context, _ string) (bool, int, error) {
			return false, 0, errors.New("hibp is down")
		},
	})

	if err := srv.checkNotBreached(context.Background(), "some-password"); err != nil {
		t.Fatalf("checkNotBreached with checker error = %v, want nil (fail open)", err)
	}
}

func containsPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

// =============================================================================
// Register breach-check Tests
// =============================================================================

func TestRegister_BreachedPassword_RejectedWithoutCreatingUser(t *testing.T) {
	registerCalled := false
	mdb := &mockDB{
		registerUserFn: func(_ context.Context, _, _ string) (string, error) {
			registerCalled = true
			return "new-user-id", nil
		},
	}
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
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v, want %v (err: %v)", status.Code(err), codes.InvalidArgument, err)
	}
	if registerCalled {
		t.Error("RegisterUser must not be called for a breached password")
	}
}

func TestRegister_BreachCheckError_FailsOpen(t *testing.T) {
	registerCalled := false
	mdb := &mockDB{
		registerUserFn: func(_ context.Context, _, _ string) (string, error) {
			registerCalled = true
			return "new-user-id", nil
		},
	}
	srv := newTestServerWithBreached(mdb, &noopMailSender{}, &mockBreachedChecker{
		isBreachedFn: func(_ context.Context, _ string) (bool, int, error) {
			return false, 0, errors.New("hibp timeout")
		},
	})
	ctx := context.Background()

	resp, err := srv.Register(ctx, &authv1.RegisterRequest{
		Email:    "new@example.com",
		Password: testPassword,
	})
	if err != nil {
		t.Fatalf("Register failed: %v (want fail open)", err)
	}
	if resp == nil || resp.UserId != "" {
		t.Errorf("resp = %+v, want generic empty-UserId response", resp)
	}
	if !registerCalled {
		t.Error("RegisterUser should still be called when the breach check fails open")
	}
}

// =============================================================================
// ChangePassword breach-check Tests
// =============================================================================

func TestChangePassword_BreachedNewPassword_RejectedWithoutUpdating(t *testing.T) {
	updateCalled := false
	mdb := &mockDB{
		getUserByIDFn: func(_ context.Context, _ string) (*model.UserInternal, error) {
			return testUser(), nil
		},
		updatePasswordFn: func(_ context.Context, _, _ string) error {
			updateCalled = true
			return nil
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
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v, want %v (err: %v)", status.Code(err), codes.InvalidArgument, err)
	}
	if updateCalled {
		t.Error("UpdatePassword must not be called for a breached new password")
	}
}

// =============================================================================
// ResetPassword breach-check Tests
// =============================================================================

func TestResetPassword_BreachedNewPassword_RejectedWithoutUpdating(t *testing.T) {
	updateCalled := false
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
		updatePasswordFn: func(_ context.Context, _, _ string) error {
			updateCalled = true
			return nil
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
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v, want %v (err: %v)", status.Code(err), codes.InvalidArgument, err)
	}
	if updateCalled {
		t.Error("UpdatePassword must not be called for a breached new password")
	}
}
