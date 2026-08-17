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
	"github.com/swayrider/swlib/security"
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

func TestLogin_DBConnectionError(t *testing.T) {
	mdb := &mockDB{
		getUserByEmailFn: func(_ context.Context, _ string) (*model.UserInternal, error) {
			return nil, errors.New("connection refused")
		},
	}
	srv := newTestServer(mdb, &noopMailSender{})
	ctx := context.Background()

	_, err := srv.Login(ctx, &authv1.LoginRequest{
		Email:    "test@example.com",
		Password: "irrelevant",
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.Internal {
		t.Errorf("code = %v, want %v", st.Code(), codes.Internal)
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

func TestLogin_StoresNormalizedIP(t *testing.T) {
	var storedIP string
	mdb := &mockDB{
		getUserByEmailFn: func(_ context.Context, _ string) (*model.UserInternal, error) {
			return testUser(), nil
		},
		createRefreshTokenFn: func(_ context.Context, _ *model.User, _, ip, _ string) (*model.RefreshToken, error) {
			storedIP = ip
			return &model.RefreshToken{
				Token:      "test-refresh-token",
				UserId:     "test-user-id",
				ValidUntil: time.Now().Add(30 * 24 * time.Hour),
			}, nil
		},
	}
	srv := newTestServer(mdb, &noopMailSender{})
	// Simulate a comma-joined chain in the context (defense in depth: the
	// server must store a single, unambiguous IP).
	ctx := context.WithValue(context.Background(), security.OrigIpKey, "1.2.3.4, 10.0.0.1")

	if _, err := srv.Login(ctx, &authv1.LoginRequest{
		Email:    "test@example.com",
		Password: testPassword,
	}); err != nil {
		t.Fatalf("Login failed: %v", err)
	}
	if storedIP != "1.2.3.4" {
		t.Errorf("stored IP = %q, want first chain entry %q", storedIP, "1.2.3.4")
	}
}

// =============================================================================
// Login lockout Tests
// =============================================================================

func testThrottleConfig() ThrottleConfig {
	return ThrottleConfig{
		LoginMaxAttempts:      5,
		LoginWindow:           15 * time.Minute,
		LoginLockoutDuration:  15 * time.Minute,
		ClientMaxAttempts:     5,
		ClientWindow:          15 * time.Minute,
		ClientLockoutDuration: 15 * time.Minute,
		EmailCooldown:         60 * time.Second,
	}
}

func TestLogin_LockedIdentifier_ReturnsUniformErrorWithoutLookup(t *testing.T) {
	lookupCalled := false
	mdb := &mockDB{
		isAttemptLockedFn: func(_ context.Context, scope db.ThrottleScope, identifier string) (bool, error) {
			if scope != db.ScopeLogin || identifier != "test@example.com" {
				t.Errorf("unexpected scope/identifier: %v/%s", scope, identifier)
			}
			return true, nil
		},
		getUserByEmailFn: func(_ context.Context, _ string) (*model.UserInternal, error) {
			lookupCalled = true
			return testUser(), nil
		},
	}
	srv := newTestServerWithThrottle(mdb, &noopMailSender{}, testThrottleConfig())
	ctx := context.Background()

	_, err := srv.Login(ctx, &authv1.LoginRequest{
		Email:    "test@example.com",
		Password: testPassword,
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.Unauthenticated {
		t.Errorf("code = %v, want %v", st.Code(), codes.Unauthenticated)
	}
	if st.Message() != "invalid email or password" {
		t.Errorf("message = %q, want %q", st.Message(), "invalid email or password")
	}
	if lookupCalled {
		t.Error("expected GetUserByEmail not to be called when locked out")
	}
}

func TestLogin_LockedNonexistentEmail_SameErrorAsLockedRealAccount(t *testing.T) {
	mdb := &mockDB{
		isAttemptLockedFn: func(_ context.Context, _ db.ThrottleScope, _ string) (bool, error) {
			return true, nil
		},
	}
	srv := newTestServerWithThrottle(mdb, &noopMailSender{}, testThrottleConfig())
	ctx := context.Background()

	_, err := srv.Login(ctx, &authv1.LoginRequest{
		Email:    "nobody-locked@example.com",
		Password: "irrelevant",
	})
	st, _ := status.FromError(err)

	_, err2 := srv.Login(ctx, &authv1.LoginRequest{
		Email:    "test@example.com",
		Password: testPassword,
	})
	st2, _ := status.FromError(err2)

	if st.Code() != st2.Code() || st.Message() != st2.Message() {
		t.Errorf("locked nonexistent-account error (%v: %q) differs from locked real-account error (%v: %q)",
			st.Code(), st.Message(), st2.Code(), st2.Message())
	}
}

func TestLogin_RecordsFailureOnUserNotFound(t *testing.T) {
	var recordedSuccess *bool
	mdb := &mockDB{
		getUserByEmailFn: func(_ context.Context, _ string) (*model.UserInternal, error) {
			return nil, db.ErrUserNotFound
		},
		recordAttemptResultFn: func(_ context.Context, scope db.ThrottleScope, identifier string, success bool, _ int, _, _ time.Duration) error {
			if scope != db.ScopeLogin || identifier != "nobody@example.com" {
				t.Errorf("unexpected scope/identifier: %v/%s", scope, identifier)
			}
			recordedSuccess = &success
			return nil
		},
	}
	srv := newTestServerWithThrottle(mdb, &noopMailSender{}, testThrottleConfig())
	ctx := context.Background()

	_, _ = srv.Login(ctx, &authv1.LoginRequest{
		Email:    "nobody@example.com",
		Password: "irrelevant",
	})
	if recordedSuccess == nil {
		t.Fatal("expected RecordAttemptResult to be called")
	}
	if *recordedSuccess {
		t.Error("expected failure to be recorded as success=false")
	}
}

func TestLogin_RecordsFailureOnWrongPassword(t *testing.T) {
	var recordedSuccess *bool
	mdb := &mockDB{
		getUserByEmailFn: func(_ context.Context, _ string) (*model.UserInternal, error) {
			return testUser(), nil
		},
		recordAttemptResultFn: func(_ context.Context, _ db.ThrottleScope, _ string, success bool, _ int, _, _ time.Duration) error {
			recordedSuccess = &success
			return nil
		},
	}
	srv := newTestServerWithThrottle(mdb, &noopMailSender{}, testThrottleConfig())
	ctx := context.Background()

	_, _ = srv.Login(ctx, &authv1.LoginRequest{
		Email:    "test@example.com",
		Password: "wrongpassword",
	})
	if recordedSuccess == nil {
		t.Fatal("expected RecordAttemptResult to be called")
	}
	if *recordedSuccess {
		t.Error("expected failure to be recorded as success=false")
	}
}

func TestLogin_DoesNotRecordOnInternalDBError(t *testing.T) {
	recordCalled := false
	mdb := &mockDB{
		getUserByEmailFn: func(_ context.Context, _ string) (*model.UserInternal, error) {
			return nil, errors.New("connection refused")
		},
		recordAttemptResultFn: func(_ context.Context, _ db.ThrottleScope, _ string, _ bool, _ int, _, _ time.Duration) error {
			recordCalled = true
			return nil
		},
	}
	srv := newTestServerWithThrottle(mdb, &noopMailSender{}, testThrottleConfig())
	ctx := context.Background()

	_, _ = srv.Login(ctx, &authv1.LoginRequest{
		Email:    "test@example.com",
		Password: "irrelevant",
	})
	if recordCalled {
		t.Error("expected RecordAttemptResult NOT to be called on an internal DB error " +
			"(recording it would let an attacker trip DB errors to lock out a victim)")
	}
}

func TestLogin_RecordsSuccessOnCorrectCredentials(t *testing.T) {
	var recordedSuccess *bool
	mdb := &mockDB{
		getUserByEmailFn: func(_ context.Context, _ string) (*model.UserInternal, error) {
			return testUser(), nil
		},
		recordAttemptResultFn: func(_ context.Context, scope db.ThrottleScope, _ string, success bool, _ int, _, _ time.Duration) error {
			if scope != db.ScopeLogin {
				t.Errorf("unexpected scope: %v", scope)
			}
			recordedSuccess = &success
			return nil
		},
	}
	srv := newTestServerWithThrottle(mdb, &noopMailSender{}, testThrottleConfig())
	ctx := context.Background()

	if _, err := srv.Login(ctx, &authv1.LoginRequest{
		Email:    "test@example.com",
		Password: testPassword,
	}); err != nil {
		t.Fatalf("Login failed: %v", err)
	}
	if recordedSuccess == nil {
		t.Fatal("expected RecordAttemptResult to be called")
	}
	if !*recordedSuccess {
		t.Error("expected success to be recorded as success=true")
	}
}

// =============================================================================
// Refresh Tests
// =============================================================================

func TestRefresh_TokenNotFound(t *testing.T) {
	mdb := &mockDB{
		consumeRefreshTokenFn: func(_ context.Context, _ string) (*model.RefreshToken, error) {
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

func TestRefresh_IPMismatchSucceeds(t *testing.T) {
	// Soft gate: an IP mismatch (or a missing IP) is logged as an anomaly
	// signal but never blocks the refresh — mobile clients legitimately
	// change IP between login and refresh.
	mdb := &mockDB{
		consumeRefreshTokenFn: func(_ context.Context, _ string) (*model.RefreshToken, error) {
			return &model.RefreshToken{
				Token:      "some-token",
				UserId:     "user-1",
				ValidUntil: time.Now().Add(time.Hour),
				Ip:         "10.0.0.1",
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
	// The context has no IP at all (security.GetOrigIp returns "") while the
	// stored token is bound to 10.0.0.1 — a mismatch — yet refresh must succeed.
	ctx := context.Background()

	resp, err := srv.Refresh(ctx, &authv1.RefreshRequest{RefreshToken: "some-token"})
	if err != nil {
		t.Fatalf("Refresh failed on IP mismatch: %v", err)
	}
	if resp.RefreshToken == "" {
		t.Error("expected a rotated refresh token")
	}
}

func TestRefresh_IPMatchSucceeds(t *testing.T) {
	// Same request with a matching forwarded IP: refresh succeeds.
	mdb := &mockDB{
		consumeRefreshTokenFn: func(_ context.Context, _ string) (*model.RefreshToken, error) {
			return &model.RefreshToken{
				Token:      "some-token",
				UserId:     "user-1",
				ValidUntil: time.Now().Add(time.Hour),
				Ip:         "10.0.0.1",
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
	ctx := context.WithValue(context.Background(), security.OrigIpKey, "10.0.0.1")

	resp, err := srv.Refresh(ctx, &authv1.RefreshRequest{RefreshToken: "some-token"})
	if err != nil {
		t.Fatalf("Refresh failed: %v", err)
	}
	if resp.RefreshToken == "" {
		t.Error("expected a rotated refresh token")
	}
}

func TestRefresh_Success(t *testing.T) {
	const storedToken = "valid-refresh-token"
	// The token must have empty IP and UA to match the context (which also returns "").
	mdb := &mockDB{
		consumeRefreshTokenFn: func(_ context.Context, _ string) (*model.RefreshToken, error) {
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

func TestRefresh_DeletesCookieSourcedToken(t *testing.T) {
	const cookieToken = "cookie-sourced-refresh-token"
	var consumedWith string

	mdb := &mockDB{
		consumeRefreshTokenFn: func(_ context.Context, token string) (*model.RefreshToken, error) {
			consumedWith = token
			return &model.RefreshToken{
				Token:      token,
				UserId:     "test-user-id",
				ValidUntil: time.Now().Add(time.Hour),
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

	// Simulate the cookie-based REST flow: AuthInterceptor populates
	// security.RefreshKey in the context from the refresh_token cookie.
	// req.RefreshToken is deliberately empty, as grpc-gateway leaves it
	// when the client only sends a cookie.
	ctx := context.WithValue(context.Background(), security.RefreshKey, cookieToken)

	_, err := srv.Refresh(ctx, &authv1.RefreshRequest{RefreshToken: ""})
	if err != nil {
		t.Fatalf("Refresh failed: %v", err)
	}
	if consumedWith != cookieToken {
		t.Errorf("ConsumeRefreshToken called with %q, want %q", consumedWith, cookieToken)
	}
}

func TestRefresh_AlreadyConsumedTokenFailsWithoutIssuingNewTokens(t *testing.T) {
	// Regression test for the TOCTOU fix: when ConsumeRefreshToken reports no
	// row was found (the token was never valid, or a concurrent Refresh call
	// already consumed it), Refresh must hard-fail rather than falling
	// through to issue a new token pair.
	var createRefreshTokenCalled bool

	mdb := &mockDB{
		consumeRefreshTokenFn: func(_ context.Context, _ string) (*model.RefreshToken, error) {
			return nil, db.ErrNoRefreshTokenFound
		},
		createRefreshTokenFn: func(_ context.Context, user *model.User, _, _, _ string) (*model.RefreshToken, error) {
			createRefreshTokenCalled = true
			return &model.RefreshToken{Token: "new-refresh-token", UserId: user.ID}, nil
		},
	}
	srv := newTestServer(mdb, &noopMailSender{})
	ctx := context.Background()

	_, err := srv.Refresh(ctx, &authv1.RefreshRequest{RefreshToken: "already-consumed-token"})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.Unauthenticated {
		t.Errorf("code = %v, want %v", st.Code(), codes.Unauthenticated)
	}
	if createRefreshTokenCalled {
		t.Error("CreateRefreshToken must not be called when the old token could not be consumed")
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

func TestGetToken_DBConnectionError(t *testing.T) {
	mdb := &mockDB{
		getServiceClientByIDFn: func(_ context.Context, _ string) (*model.ServiceClientInternal, error) {
			return nil, errors.New("connection refused")
		},
	}
	srv := newTestServer(mdb, &noopMailSender{})
	ctx := context.Background()

	_, err := srv.GetToken(ctx, &authv1.GetTokenRequest{
		ClientId:     "test-client-id",
		ClientSecret: "secret",
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.Internal {
		t.Errorf("code = %v, want %v", st.Code(), codes.Internal)
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

// =============================================================================
// GetToken lockout Tests
// =============================================================================

func TestGetToken_LockedClient_ReturnsUniformErrorWithoutLookup(t *testing.T) {
	lookupCalled := false
	mdb := &mockDB{
		isAttemptLockedFn: func(_ context.Context, scope db.ThrottleScope, identifier string) (bool, error) {
			if scope != db.ScopeGetToken || identifier != "test-client-id" {
				t.Errorf("unexpected scope/identifier: %v/%s", scope, identifier)
			}
			return true, nil
		},
		getServiceClientByIDFn: func(_ context.Context, _ string) (*model.ServiceClientInternal, error) {
			lookupCalled = true
			return testServiceClient([]string{"read"}), nil
		},
	}
	srv := newTestServerWithThrottle(mdb, &noopMailSender{}, testThrottleConfig())
	ctx := context.Background()

	_, err := srv.GetToken(ctx, &authv1.GetTokenRequest{
		ClientId:     "test-client-id",
		ClientSecret: testSecret,
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.Unauthenticated {
		t.Errorf("code = %v, want %v", st.Code(), codes.Unauthenticated)
	}
	if st.Message() != "service client authentication error" {
		t.Errorf("message = %q, want %q", st.Message(), "service client authentication error")
	}
	if lookupCalled {
		t.Error("expected GetServiceClientByID not to be called when locked out")
	}
}

func TestGetToken_RecordsFailureOnClientNotFound(t *testing.T) {
	var recordedSuccess *bool
	mdb := &mockDB{
		getServiceClientByIDFn: func(_ context.Context, _ string) (*model.ServiceClientInternal, error) {
			return nil, db.ErrServiceClientNotFound
		},
		recordAttemptResultFn: func(_ context.Context, scope db.ThrottleScope, identifier string, success bool, _ int, _, _ time.Duration) error {
			if scope != db.ScopeGetToken || identifier != "unknown" {
				t.Errorf("unexpected scope/identifier: %v/%s", scope, identifier)
			}
			recordedSuccess = &success
			return nil
		},
	}
	srv := newTestServerWithThrottle(mdb, &noopMailSender{}, testThrottleConfig())
	ctx := context.Background()

	_, _ = srv.GetToken(ctx, &authv1.GetTokenRequest{
		ClientId:     "unknown",
		ClientSecret: "secret",
	})
	if recordedSuccess == nil {
		t.Fatal("expected RecordAttemptResult to be called")
	}
	if *recordedSuccess {
		t.Error("expected failure to be recorded as success=false")
	}
}

func TestGetToken_RecordsFailureOnWrongSecret(t *testing.T) {
	var recordedSuccess *bool
	mdb := &mockDB{
		getServiceClientByIDFn: func(_ context.Context, _ string) (*model.ServiceClientInternal, error) {
			return testServiceClient([]string{"read"}), nil
		},
		recordAttemptResultFn: func(_ context.Context, _ db.ThrottleScope, _ string, success bool, _ int, _, _ time.Duration) error {
			recordedSuccess = &success
			return nil
		},
	}
	srv := newTestServerWithThrottle(mdb, &noopMailSender{}, testThrottleConfig())
	ctx := context.Background()

	_, _ = srv.GetToken(ctx, &authv1.GetTokenRequest{
		ClientId:     "test-client-id",
		ClientSecret: "wrong-secret",
	})
	if recordedSuccess == nil {
		t.Fatal("expected RecordAttemptResult to be called")
	}
	if *recordedSuccess {
		t.Error("expected failure to be recorded as success=false")
	}
}

func TestGetToken_DoesNotRecordOnInternalDBError(t *testing.T) {
	recordCalled := false
	mdb := &mockDB{
		getServiceClientByIDFn: func(_ context.Context, _ string) (*model.ServiceClientInternal, error) {
			return nil, errors.New("connection refused")
		},
		recordAttemptResultFn: func(_ context.Context, _ db.ThrottleScope, _ string, _ bool, _ int, _, _ time.Duration) error {
			recordCalled = true
			return nil
		},
	}
	srv := newTestServerWithThrottle(mdb, &noopMailSender{}, testThrottleConfig())
	ctx := context.Background()

	_, _ = srv.GetToken(ctx, &authv1.GetTokenRequest{
		ClientId:     "test-client-id",
		ClientSecret: "secret",
	})
	if recordCalled {
		t.Error("expected RecordAttemptResult NOT to be called on an internal DB error")
	}
}

func TestGetToken_RecordsSuccessOnCorrectCredentials(t *testing.T) {
	var recordedSuccess *bool
	mdb := &mockDB{
		getServiceClientByIDFn: func(_ context.Context, _ string) (*model.ServiceClientInternal, error) {
			return testServiceClient([]string{"read"}), nil
		},
		recordAttemptResultFn: func(_ context.Context, scope db.ThrottleScope, _ string, success bool, _ int, _, _ time.Duration) error {
			if scope != db.ScopeGetToken {
				t.Errorf("unexpected scope: %v", scope)
			}
			recordedSuccess = &success
			return nil
		},
	}
	srv := newTestServerWithThrottle(mdb, &noopMailSender{}, testThrottleConfig())
	ctx := context.Background()

	if _, err := srv.GetToken(ctx, &authv1.GetTokenRequest{
		ClientId:     "test-client-id",
		ClientSecret: testSecret,
	}); err != nil {
		t.Fatalf("GetToken failed: %v", err)
	}
	if recordedSuccess == nil {
		t.Fatal("expected RecordAttemptResult to be called")
	}
	if !*recordedSuccess {
		t.Error("expected success to be recorded as success=true")
	}
}
