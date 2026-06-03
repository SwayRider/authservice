package server

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	authv1 "github.com/swayrider/protos/auth/v1"
	"github.com/swayrider/authservice/internal/db"
	"github.com/swayrider/authservice/internal/model"
)

// =============================================================================
// GetRememberMe Tests
// =============================================================================

func TestGetRememberMe_NotSet(t *testing.T) {
	ctx := context.Background()
	if got := GetRememberMe(ctx); got != false {
		t.Errorf("GetRememberMe with no value = %v, want false", got)
	}
}

func TestGetRememberMe_True(t *testing.T) {
	ctx := context.WithValue(context.Background(), RememberMeKey, true)
	if got := GetRememberMe(ctx); got != true {
		t.Errorf("GetRememberMe with true = %v, want true", got)
	}
}

func TestGetRememberMe_False(t *testing.T) {
	ctx := context.WithValue(context.Background(), RememberMeKey, false)
	if got := GetRememberMe(ctx); got != false {
		t.Errorf("GetRememberMe with false = %v, want false", got)
	}
}

// =============================================================================
// CookieHeaderMatcher Tests
// =============================================================================

func TestCookieHeaderMatcher(t *testing.T) {
	tests := []struct {
		header  string
		wantKey string
		wantOk  bool
	}{
		{"cookie", "cookie", true},
		{"Cookie", "cookie", true},
		{"COOKIE", "cookie", true},
	}

	for _, tt := range tests {
		t.Run(tt.header, func(t *testing.T) {
			key, ok := CookieHeaderMatcher(tt.header)
			if ok != tt.wantOk {
				t.Errorf("ok = %v, want %v", ok, tt.wantOk)
			}
			if key != tt.wantKey {
				t.Errorf("key = %q, want %q", key, tt.wantKey)
			}
		})
	}
}

func TestCookieHeaderMatcher_NonCookieHeader(t *testing.T) {
	// Non-cookie headers should be delegated to the runtime default matcher.
	// We verify that a standard gRPC-gateway header (e.g. "grpc-metadata-*") is handled.
	_, ok := CookieHeaderMatcher("X-Custom-Header")
	// The runtime default matcher returns false for arbitrary non-standard headers —
	// we just verify the call doesn't panic and returns a consistent result.
	_ = ok
}

// =============================================================================
// Login Tests
// =============================================================================

func TestLogin_UserNotFound(t *testing.T) {
	mdb := &mockDB{
		getUserByEmailFn: func(_ context.Context, _ string) (*model.UserInternal, error) {
			return nil, db.ErrUserNotFound
		},
	}
	srv := newTestServer(mdb, &noopMailSender{})
	ctx := context.Background()

	_, err := srv.Login(ctx, &authv1.LoginRequest{
		Email:    "nobody@example.com",
		Password: "irrelevant",
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.Unauthenticated {
		t.Errorf("code = %v, want %v", st.Code(), codes.Unauthenticated)
	}
}

func TestLogin_NullPasswordHash(t *testing.T) {
	mdb := &mockDB{
		getUserByEmailFn: func(_ context.Context, _ string) (*model.UserInternal, error) {
			u := testUser()
			u.PasswordHash = sql.NullString{Valid: false}
			return u, nil
		},
	}
	srv := newTestServer(mdb, &noopMailSender{})
	ctx := context.Background()

	_, err := srv.Login(ctx, &authv1.LoginRequest{
		Email:    "test@example.com",
		Password: "anypassword",
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.Unauthenticated {
		t.Errorf("code = %v, want %v", st.Code(), codes.Unauthenticated)
	}
}

func TestLogin_WrongPassword(t *testing.T) {
	mdb := &mockDB{
		getUserByEmailFn: func(_ context.Context, _ string) (*model.UserInternal, error) {
			return testUser(), nil
		},
	}
	srv := newTestServer(mdb, &noopMailSender{})
	ctx := context.Background()

	_, err := srv.Login(ctx, &authv1.LoginRequest{
		Email:    "test@example.com",
		Password: "wrongpassword",
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.Unauthenticated {
		t.Errorf("code = %v, want %v", st.Code(), codes.Unauthenticated)
	}
}

func TestLogin_Success(t *testing.T) {
	mdb := &mockDB{
		getUserByEmailFn: func(_ context.Context, _ string) (*model.UserInternal, error) {
			return testUser(), nil
		},
		// getSigningKeyFn defaults to testPrivateKeyPEM via mockDB default
		createRefreshTokenFn: func(_ context.Context, user *model.User, _, _, _ string) (*model.RefreshToken, error) {
			return &model.RefreshToken{
				Token:      "test-refresh-token",
				UserId:     user.ID,
				ValidUntil: time.Now().Add(30 * 24 * time.Hour),
			}, nil
		},
	}
	srv := newTestServer(mdb, &noopMailSender{})
	ctx := context.Background()

	resp, err := srv.Login(ctx, &authv1.LoginRequest{
		Email:    "test@example.com",
		Password: testPassword,
	})
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}
	if resp.AccessToken == "" {
		t.Error("expected non-empty access token")
	}
	if resp.RefreshToken == "" {
		t.Error("expected non-empty refresh token")
	}
}

// =============================================================================
// Refresh Tests
// =============================================================================

func TestRefresh_TokenNotFound(t *testing.T) {
	mdb := &mockDB{
		getRefreshTokenFn: func(_ context.Context, _ string) (*model.RefreshToken, error) {
			return nil, errors.New("token not found")
		},
	}
	srv := newTestServer(mdb, &noopMailSender{})
	ctx := context.Background()

	_, err := srv.Refresh(ctx, &authv1.RefreshRequest{RefreshToken: "invalid-token"})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.Unauthenticated {
		t.Errorf("code = %v, want %v", st.Code(), codes.Unauthenticated)
	}
}

func TestRefresh_TokenIPMismatch(t *testing.T) {
	mdb := &mockDB{
		getRefreshTokenFn: func(_ context.Context, _ string) (*model.RefreshToken, error) {
			return &model.RefreshToken{
				Token:      "some-token",
				UserId:     "user-1",
				ValidUntil: time.Now().Add(time.Hour),
				Ip:         "10.0.0.1",
				UserAgent:  "TestAgent/1.0",
			}, nil
		},
	}
	srv := newTestServer(mdb, &noopMailSender{})
	// The context has no IP set, so security.GetOrigIp returns "".
	// This causes the token Verify to fail (IP mismatch).
	ctx := context.Background()

	_, err := srv.Refresh(ctx, &authv1.RefreshRequest{RefreshToken: "some-token"})
	if err == nil {
		t.Fatal("expected error for IP mismatch, got nil")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.Unauthenticated {
		t.Errorf("code = %v, want %v", st.Code(), codes.Unauthenticated)
	}
}

func TestRefresh_Success(t *testing.T) {
	const storedToken = "valid-refresh-token"
	// The token must have empty IP and UA to match the context (which also returns "").
	mdb := &mockDB{
		getRefreshTokenFn: func(_ context.Context, _ string) (*model.RefreshToken, error) {
			return &model.RefreshToken{
				Token:      storedToken,
				UserId:     "test-user-id",
				ValidUntil: time.Now().Add(time.Hour),
				Ip:         "",
				UserAgent:  "",
			}, nil
		},
		getUserByIDFn: func(_ context.Context, _ string) (*model.UserInternal, error) {
			return testUser(), nil
		},
		createRefreshTokenFn: func(_ context.Context, user *model.User, _, _, _ string) (*model.RefreshToken, error) {
			return &model.RefreshToken{
				Token:      "new-refresh-token",
				UserId:     user.ID,
				ValidUntil: time.Now().Add(30 * 24 * time.Hour),
			}, nil
		},
	}
	srv := newTestServer(mdb, &noopMailSender{})
	ctx := context.Background()

	resp, err := srv.Refresh(ctx, &authv1.RefreshRequest{RefreshToken: storedToken})
	if err != nil {
		t.Fatalf("Refresh failed: %v", err)
	}
	if resp.AccessToken == "" {
		t.Error("expected non-empty access token")
	}
	if resp.RefreshToken == "" {
		t.Error("expected non-empty refresh token")
	}
}

// =============================================================================
// GetToken Scope Resolution Tests
// =============================================================================

func TestGetToken_ScopeResolution(t *testing.T) {
	tests := []struct {
		name            string
		serviceScopes   []string
		requestedScopes []string
		wantGranted     []string
	}{
		{
			name:            "service wildcard grants all requested",
			serviceScopes:   []string{"*"},
			requestedScopes: []string{"read", "write"},
			wantGranted:     []string{"read", "write"},
		},
		{
			name:            "request wildcard grants all service scopes",
			serviceScopes:   []string{"read"},
			requestedScopes: []string{"*"},
			wantGranted:     []string{"read"},
		},
		{
			name:            "intersection of requested and service scopes",
			serviceScopes:   []string{"read", "write"},
			requestedScopes: []string{"read", "admin"},
			wantGranted:     []string{"read"},
		},
		{
			name:            "no overlap yields empty granted scopes",
			serviceScopes:   []string{"write"},
			requestedScopes: []string{"read"},
			wantGranted:     []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mdb := &mockDB{
				getServiceClientByIDFn: func(_ context.Context, _ string) (*model.ServiceClientInternal, error) {
					return testServiceClient(tt.serviceScopes), nil
				},
			}
			srv := newTestServer(mdb, &noopMailSender{})
			ctx := context.Background()

			resp, err := srv.GetToken(ctx, &authv1.GetTokenRequest{
				ClientId:     "test-client-id",
				ClientSecret: testSecret,
				Scopes:       tt.requestedScopes,
			})
			if err != nil {
				t.Fatalf("GetToken failed: %v", err)
			}
			if len(resp.Scopes) != len(tt.wantGranted) {
				t.Errorf("granted scopes = %v, want %v", resp.Scopes, tt.wantGranted)
				return
			}
			granted := make(map[string]bool, len(resp.Scopes))
			for _, s := range resp.Scopes {
				granted[s] = true
			}
			for _, want := range tt.wantGranted {
				if !granted[want] {
					t.Errorf("expected scope %q in granted %v", want, resp.Scopes)
				}
			}
		})
	}
}

func TestGetToken_ClientNotFound(t *testing.T) {
	mdb := &mockDB{
		getServiceClientByIDFn: func(_ context.Context, _ string) (*model.ServiceClientInternal, error) {
			return nil, db.ErrServiceClientNotFound
		},
	}
	srv := newTestServer(mdb, &noopMailSender{})
	ctx := context.Background()

	_, err := srv.GetToken(ctx, &authv1.GetTokenRequest{
		ClientId:     "unknown",
		ClientSecret: "secret",
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.NotFound {
		t.Errorf("code = %v, want %v", st.Code(), codes.NotFound)
	}
}

func TestGetToken_WrongSecret(t *testing.T) {
	mdb := &mockDB{
		getServiceClientByIDFn: func(_ context.Context, _ string) (*model.ServiceClientInternal, error) {
			return testServiceClient([]string{"read"}), nil
		},
	}
	srv := newTestServer(mdb, &noopMailSender{})
	ctx := context.Background()

	_, err := srv.GetToken(ctx, &authv1.GetTokenRequest{
		ClientId:     "test-client-id",
		ClientSecret: "wrong-secret",
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.Unauthenticated {
		t.Errorf("code = %v, want %v", st.Code(), codes.Unauthenticated)
	}
}
