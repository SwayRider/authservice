package server

import (
	"context"
	"testing"
	"time"

	"github.com/swayrider/authservice/internal/model"
	authv1 "github.com/swayrider/protos/auth/v1"
)

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
