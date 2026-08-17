package server

import (
	"context"
	"testing"

	jwt5 "github.com/golang-jwt/jwt/v5"
	"github.com/swayrider/authservice/internal/model"
	authv1 "github.com/swayrider/protos/auth/v1"
	"github.com/swayrider/swlib/jwt"
	"github.com/swayrider/swlib/security"
)

// claimsContext returns a context with valid JWT claims for the given user ID,
// as set by the auth interceptor for authenticated requests.
func claimsContext(userID string) context.Context {
	claims := &jwt.Claims{
		RegisteredClaims: jwt5.RegisteredClaims{Subject: userID},
	}
	return context.WithValue(context.Background(), security.ClaimsKey, claims)
}

func TestChangePassword_RevokesRefreshTokensOnSuccess(t *testing.T) {
	var revokedUserID string
	mdb := &mockDB{
		getUserByIDFn: func(_ context.Context, _ string) (*model.UserInternal, error) {
			return testUser(), nil
		},
		deleteRefreshTokensByUserIDFn: func(_ context.Context, userId string) error {
			revokedUserID = userId
			return nil
		},
	}
	srv := newTestServer(mdb, &noopMailSender{})
	ctx := claimsContext("test-user-id")

	_, err := srv.ChangePassword(ctx, &authv1.ChangePasswordRequest{
		OldPassword: testPassword,
		NewPassword: "AnotherStr0ng!Passw0rd",
	})
	if err != nil {
		t.Fatalf("ChangePassword failed: %v", err)
	}
	if revokedUserID != "test-user-id" {
		t.Errorf("DeleteRefreshTokensByUserID called with %q, want %q", revokedUserID, "test-user-id")
	}
}

func TestChangePassword_DoesNotRevokeOnWrongOldPassword(t *testing.T) {
	revokeCalled := false
	mdb := &mockDB{
		getUserByIDFn: func(_ context.Context, _ string) (*model.UserInternal, error) {
			return testUser(), nil
		},
		deleteRefreshTokensByUserIDFn: func(_ context.Context, _ string) error {
			revokeCalled = true
			return nil
		},
	}
	srv := newTestServer(mdb, &noopMailSender{})
	ctx := claimsContext("test-user-id")

	_, err := srv.ChangePassword(ctx, &authv1.ChangePasswordRequest{
		OldPassword: "wrong-old-password",
		NewPassword: "AnotherStr0ng!Passw0rd",
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if revokeCalled {
		t.Error("DeleteRefreshTokensByUserID should not be called when old password is wrong")
	}
}
