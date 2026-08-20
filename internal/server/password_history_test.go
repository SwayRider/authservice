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
// checkNotReused helper Tests
// =============================================================================

func TestCheckNotReused_Reused_RejectsWithPrefix(t *testing.T) {
	srv := newTestServer(&mockDB{
		checkPasswordReuseFn: func(_ context.Context, _, _ string) (bool, error) {
			return true, nil
		},
	}, &noopMailSender{})

	err := srv.checkNotReused(context.Background(), "test-user-id", "some-password")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("code = %v, want %v", status.Code(err), codes.InvalidArgument)
	}
	if msg := status.Convert(err).Message(); !containsPrefix(msg, ErrPasswordReusedPrefix) {
		t.Errorf("message %q does not start with prefix %q", msg, ErrPasswordReusedPrefix)
	}
}

func TestCheckNotReused_NotReused_Allows(t *testing.T) {
	srv := newTestServer(&mockDB{
		checkPasswordReuseFn: func(_ context.Context, _, _ string) (bool, error) {
			return false, nil
		},
	}, &noopMailSender{})

	if err := srv.checkNotReused(context.Background(), "test-user-id", "some-password"); err != nil {
		t.Fatalf("checkNotReused = %v, want nil", err)
	}
}

func TestCheckNotReused_DBError_FailsOpen(t *testing.T) {
	srv := newTestServer(&mockDB{
		checkPasswordReuseFn: func(_ context.Context, _, _ string) (bool, error) {
			return false, errors.New("history table unavailable")
		},
	}, &noopMailSender{})

	if err := srv.checkNotReused(context.Background(), "test-user-id", "some-password"); err != nil {
		t.Fatalf("checkNotReused with DB error = %v, want nil (fail open)", err)
	}
}

// =============================================================================
// ChangePassword reuse Tests
// =============================================================================

func TestChangePassword_ReusedNewPassword_RejectedWithoutUpdating(t *testing.T) {
	updateCalled := false
	historyCalled := false
	mdb := &mockDB{
		getUserByIDFn: func(_ context.Context, _ string) (*model.UserInternal, error) {
			return testUser(), nil
		},
		checkPasswordReuseFn: func(_ context.Context, _, _ string) (bool, error) {
			return true, nil
		},
		updatePasswordFn: func(_ context.Context, _, _ string) error {
			updateCalled = true
			return nil
		},
		addToPasswordHistoryFn: func(_ context.Context, _, _ string) error {
			historyCalled = true
			return nil
		},
	}
	srv := newTestServer(mdb, &noopMailSender{})
	ctx := claimsContext("test-user-id")

	_, err := srv.ChangePassword(ctx, &authv1.ChangePasswordRequest{
		OldPassword: testPassword,
		NewPassword: "AnotherStr0ng!Passw0rd",
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v, want %v (err: %v)", status.Code(err), codes.InvalidArgument, err)
	}
	if updateCalled {
		t.Error("UpdatePassword must not be called for a reused new password")
	}
	if historyCalled {
		t.Error("AddToPasswordHistory must not be called for a rejected new password")
	}
}

func TestChangePassword_ReuseCheckError_FailsOpenAndRecordsHistory(t *testing.T) {
	updateCalled := false
	historyCalled := false
	mdb := &mockDB{
		getUserByIDFn: func(_ context.Context, _ string) (*model.UserInternal, error) {
			return testUser(), nil
		},
		checkPasswordReuseFn: func(_ context.Context, _, _ string) (bool, error) {
			return false, errors.New("history table unavailable")
		},
		updatePasswordFn: func(_ context.Context, _, _ string) error {
			updateCalled = true
			return nil
		},
		addToPasswordHistoryFn: func(_ context.Context, _, _ string) error {
			historyCalled = true
			return nil
		},
	}
	srv := newTestServer(mdb, &noopMailSender{})
	ctx := claimsContext("test-user-id")

	if _, err := srv.ChangePassword(ctx, &authv1.ChangePasswordRequest{
		OldPassword: testPassword,
		NewPassword: "AnotherStr0ng!Passw0rd",
	}); err != nil {
		t.Fatalf("ChangePassword failed: %v (want fail open)", err)
	}
	if !updateCalled {
		t.Error("UpdatePassword should still be called when the reuse check fails open")
	}
	if !historyCalled {
		t.Error("AddToPasswordHistory should be called after a successful change")
	}
}

// =============================================================================
// ResetPassword reuse Tests
// =============================================================================

func TestResetPassword_ReusedNewPassword_RejectedWithoutUpdating(t *testing.T) {
	updateCalled := false
	historyCalled := false
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
		updatePasswordFn: func(_ context.Context, _, _ string) error {
			updateCalled = true
			return nil
		},
		addToPasswordHistoryFn: func(_ context.Context, _, _ string) error {
			historyCalled = true
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
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v, want %v (err: %v)", status.Code(err), codes.InvalidArgument, err)
	}
	if updateCalled {
		t.Error("UpdatePassword must not be called for a reused new password")
	}
	if historyCalled {
		t.Error("AddToPasswordHistory must not be called for a rejected new password")
	}
}

// =============================================================================
// Register history seeding Tests
// =============================================================================

func TestRegister_SeedsPasswordHistory(t *testing.T) {
	var registeredHash string // the hash Register passed to RegisterUser
	var seededUserID, seededHash string
	mdb := &mockDB{
		registerUserFn: func(_ context.Context, _, hashedPassword string) (string, error) {
			registeredHash = hashedPassword
			return "new-user-id", nil
		},
		addToPasswordHistoryFn: func(_ context.Context, userID, passwordHash string) error {
			seededUserID = userID
			seededHash = passwordHash
			return nil
		},
	}
	srv := newTestServer(mdb, &noopMailSender{})
	ctx := context.Background()

	if _, err := srv.Register(ctx, &authv1.RegisterRequest{
		Email:    "new@example.com",
		Password: testPassword,
	}); err != nil {
		t.Fatalf("Register failed: %v", err)
	}
	if registeredHash == "" {
		t.Fatal("RegisterUser was not called")
	}
	if seededUserID != "new-user-id" {
		t.Errorf("AddToPasswordHistory called with userID %q, want %q", seededUserID, "new-user-id")
	}
	// The seeded hash must be exactly the hash that was stored as the user's
	// password -- history and users.password_hash stay in sync.
	if seededHash != registeredHash {
		t.Errorf("AddToPasswordHistory hash differs from the stored password hash")
	}
}
