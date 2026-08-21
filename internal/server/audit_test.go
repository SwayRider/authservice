package server

import (
	"context"
	"testing"
	"time"

	"github.com/swayrider/authservice/internal/db"
	"github.com/swayrider/authservice/internal/model"
	authv1 "github.com/swayrider/protos/auth/v1"
)

// waitForAuditEvent drains a single event from srv's AuditWriter, failing the
// test if none arrives shortly. Handlers emit asynchronously (a non-blocking
// channel send), so tests must read from the writer's own channel rather
// than observing a side effect synchronously after the handler returns.
func waitForAuditEvent(t *testing.T, srv *AuthServer) db.AuditEvent {
	t.Helper()
	select {
	case ev := <-srv.audit.Chan():
		return ev
	case <-time.After(2 * time.Second):
		t.Fatal("expected an audit event, but none arrived")
		return db.AuditEvent{}
	}
}

func assertNoAuditEvent(t *testing.T, srv *AuthServer) {
	t.Helper()
	select {
	case ev := <-srv.audit.Chan():
		t.Fatalf("expected no audit event, but got %v", ev.EventType)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestLogin_EmitsAuditLoginSuccess(t *testing.T) {
	mdb := &mockDB{
		getUserByEmailFn: func(_ context.Context, _ string) (*model.UserInternal, error) {
			return testUser(), nil
		},
	}
	srv := newTestServer(mdb, &noopMailSender{})

	if _, err := srv.Login(context.Background(), &authv1.LoginRequest{
		Email:    "test@example.com",
		Password: testPassword,
	}); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	ev := waitForAuditEvent(t, srv)
	if ev.EventType != db.AuditLoginSuccess {
		t.Errorf("EventType = %q, want %q", ev.EventType, db.AuditLoginSuccess)
	}
	if ev.UserID == nil || *ev.UserID != "test-user-id" {
		t.Errorf("UserID = %v, want test-user-id", ev.UserID)
	}
}

func TestLogin_EmitsAuditLoginFailureOnWrongPassword(t *testing.T) {
	mdb := &mockDB{
		getUserByEmailFn: func(_ context.Context, _ string) (*model.UserInternal, error) {
			return testUser(), nil
		},
	}
	srv := newTestServer(mdb, &noopMailSender{})

	_, _ = srv.Login(context.Background(), &authv1.LoginRequest{
		Email:    "test@example.com",
		Password: "wrong-password",
	})

	ev := waitForAuditEvent(t, srv)
	if ev.EventType != db.AuditLoginFailure {
		t.Errorf("EventType = %q, want %q", ev.EventType, db.AuditLoginFailure)
	}
	if ev.Email != "test@example.com" {
		t.Errorf("Email = %q, want test@example.com", ev.Email)
	}
}

func TestLogin_EmitsAuditAccountLockedOnLockoutTransition(t *testing.T) {
	mdb := &mockDB{
		getUserByEmailFn: func(_ context.Context, _ string) (*model.UserInternal, error) {
			return nil, db.ErrUserNotFound
		},
		// Simulates RecordAttemptResult reporting that this failure was the
		// one that crossed the lockout threshold.
		recordAttemptResultFn: func(_ context.Context, _ db.ThrottleScope, _ string, _ bool, _ int, _, _ time.Duration) (bool, error) {
			return true, nil
		},
	}
	srv := newTestServerWithThrottle(mdb, &noopMailSender{}, testThrottleConfig())

	_, _ = srv.Login(context.Background(), &authv1.LoginRequest{
		Email:    "nobody@example.com",
		Password: "irrelevant",
	})

	// recordLoginAttempt (which emits the lockout transition) runs before
	// the handler's own auditLoginFailure call, so account_locked arrives
	// first -- but the exact order isn't the point here, just that both
	// events are emitted for a lockout-triggering failure.
	got := map[db.AuditEventType]bool{
		waitForAuditEvent(t, srv).EventType: true,
		waitForAuditEvent(t, srv).EventType: true,
	}
	if !got[db.AuditLoginFailure] {
		t.Error("expected an auth.login.failure event")
	}
	if !got[db.AuditAccountLocked] {
		t.Error("expected an auth.account_locked event")
	}
}

func TestRegister_EmitsAuditRegister(t *testing.T) {
	mdb := &mockDB{
		registerUserFn: func(_ context.Context, _, _ string) (string, error) {
			return "new-user-id", nil
		},
	}
	srv := newTestServer(mdb, &noopMailSender{})

	if _, err := srv.Register(context.Background(), &authv1.RegisterRequest{
		Email:    "new@example.com",
		Password: testPassword,
	}); err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	ev := waitForAuditEvent(t, srv)
	if ev.EventType != db.AuditRegister {
		t.Errorf("EventType = %q, want %q", ev.EventType, db.AuditRegister)
	}
	if ev.UserID == nil || *ev.UserID != "new-user-id" {
		t.Errorf("UserID = %v, want new-user-id", ev.UserID)
	}
}

func TestChangePassword_EmitsAuditPasswordChange(t *testing.T) {
	mdb := &mockDB{
		getUserByIDFn: func(_ context.Context, _ string) (*model.UserInternal, error) {
			return testUser(), nil
		},
	}
	srv := newTestServer(mdb, &noopMailSender{})
	ctx := claimsContext("test-user-id")

	if _, err := srv.ChangePassword(ctx, &authv1.ChangePasswordRequest{
		OldPassword: testPassword,
		NewPassword: "AnotherStr0ng!Passw0rd",
	}); err != nil {
		t.Fatalf("ChangePassword failed: %v", err)
	}

	ev := waitForAuditEvent(t, srv)
	if ev.EventType != db.AuditPasswordChange {
		t.Errorf("EventType = %q, want %q", ev.EventType, db.AuditPasswordChange)
	}
}

func TestResetPassword_EmitsAuditPasswordReset(t *testing.T) {
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
	srv := newTestServer(mdb, &noopMailSender{})

	if _, err := srv.ResetPassword(context.Background(), &authv1.ResetPasswordRequest{
		UserId:      "test-user-id",
		Token:       "valid-reset-token",
		NewPassword: "AnotherStr0ng!Passw0rd",
	}); err != nil {
		t.Fatalf("ResetPassword failed: %v", err)
	}

	ev := waitForAuditEvent(t, srv)
	if ev.EventType != db.AuditPasswordReset {
		t.Errorf("EventType = %q, want %q", ev.EventType, db.AuditPasswordReset)
	}
}

func TestCreateAdmin_EmitsAuditAdminCreateWithActor(t *testing.T) {
	mdb := &mockDB{
		createAdminUserFn: func(_ context.Context, _, _ string) (string, error) {
			return "new-admin-id", nil
		},
		getUserByIDFn: func(_ context.Context, id string) (*model.UserInternal, error) {
			u := testUser()
			u.ID = id
			return u, nil
		},
	}
	srv := newTestServer(mdb, &noopMailSender{})
	ctx := claimsContext("acting-admin-id")

	if _, err := srv.CreateAdmin(ctx, &authv1.CreateAdminRequest{
		Email:    "newadmin@example.com",
		Password: testPassword,
	}); err != nil {
		t.Fatalf("CreateAdmin failed: %v", err)
	}

	ev := waitForAuditEvent(t, srv)
	if ev.EventType != db.AuditAdminCreate {
		t.Errorf("EventType = %q, want %q", ev.EventType, db.AuditAdminCreate)
	}
	if ev.UserID == nil || *ev.UserID != "new-admin-id" {
		t.Errorf("UserID = %v, want new-admin-id", ev.UserID)
	}
	if ev.Metadata["actor_user_id"] != "acting-admin-id" {
		t.Errorf("Metadata[actor_user_id] = %v, want acting-admin-id", ev.Metadata["actor_user_id"])
	}
}

func TestLogin_DoesNotEmitAuditOnInternalDBError(t *testing.T) {
	mdb := &mockDB{
		getUserByEmailFn: func(_ context.Context, _ string) (*model.UserInternal, error) {
			return nil, context.DeadlineExceeded
		},
	}
	srv := newTestServer(mdb, &noopMailSender{})

	_, _ = srv.Login(context.Background(), &authv1.LoginRequest{
		Email:    "test@example.com",
		Password: "irrelevant",
	})

	assertNoAuditEvent(t, srv)
}

func TestLogout_EmitsAuditLogout(t *testing.T) {
	mdb := &mockDB{}
	srv := newTestServer(mdb, &noopMailSender{})

	if _, err := srv.Logout(context.Background(), &authv1.LogoutRequest{
		RefreshToken: "some-token",
	}); err != nil {
		t.Fatalf("Logout failed: %v", err)
	}

	ev := waitForAuditEvent(t, srv)
	if ev.EventType != db.AuditLogout {
		t.Errorf("EventType = %q, want %q", ev.EventType, db.AuditLogout)
	}
}

// =============================================================================
// MFA audit events
// =============================================================================

func TestSetupMFA_EmitsAuditMFASetupStarted(t *testing.T) {
	mdb := &mockDB{
		getUserByIDFn: func(_ context.Context, _ string) (*model.UserInternal, error) {
			return testUser(), nil
		},
		getMFAStatusFn: func(_ context.Context, _ string) (bool, error) {
			return false, nil
		},
		createMFASecretFn: func(_ context.Context, _, _ string) error {
			return nil
		},
	}
	srv := newTestServerWithMFA(mdb, &noopMailSender{}, testMFAConfig())
	ctx := claimsContext("test-user-id")

	if _, err := srv.SetupMFA(ctx, &authv1.SetupMFARequest{}); err != nil {
		t.Fatalf("SetupMFA failed: %v", err)
	}

	ev := waitForAuditEvent(t, srv)
	if ev.EventType != db.AuditMFASetupStarted {
		t.Errorf("EventType = %q, want %q", ev.EventType, db.AuditMFASetupStarted)
	}
	if ev.UserID == nil || *ev.UserID != "test-user-id" {
		t.Errorf("UserID = %v, want test-user-id", ev.UserID)
	}
}

func TestEnableMFA_EmitsAuditMFAEnabledAndBackupCodes(t *testing.T) {
	mdb := &mockDB{
		getUserByIDFn: func(_ context.Context, _ string) (*model.UserInternal, error) {
			return testUser(), nil
		},
		getMFAStatusFn: func(_ context.Context, _ string) (bool, error) {
			return false, nil
		},
		getMFASecretFn: func(_ context.Context, _ string) (*db.MFAUser, error) {
			return &db.MFAUser{UserID: "test-user-id", Enabled: false, Secret: testMFASecret}, nil
		},
		enableMFAFn: func(_ context.Context, _ string) error {
			return nil
		},
		storeBackupCodeHashesFn: func(_ context.Context, _ string, _ []string) error {
			return nil
		},
	}
	srv := newTestServerWithMFA(mdb, &noopMailSender{}, testMFAConfig())
	ctx := claimsContext("test-user-id")

	if _, err := srv.EnableMFA(ctx, &authv1.EnableMFARequest{Code: testMFACode(t, srv)}); err != nil {
		t.Fatalf("EnableMFA failed: %v", err)
	}

	got := map[db.AuditEventType]bool{
		waitForAuditEvent(t, srv).EventType: true,
		waitForAuditEvent(t, srv).EventType: true,
	}
	if !got[db.AuditMFAEnabled] {
		t.Error("expected an auth.mfa_enabled event")
	}
	if !got[db.AuditMFABackupCodesGenerated] {
		t.Error("expected an auth.mfa_backup_codes_generated event")
	}
}

func TestDisableMFA_EmitsAuditMFADisabled(t *testing.T) {
	mdb := &mockDB{
		getUserByIDFn: func(_ context.Context, _ string) (*model.UserInternal, error) {
			return testUser(), nil
		},
		disableMFAFn: func(_ context.Context, _ string) error {
			return nil
		},
	}
	srv := newTestServerWithMFA(mdb, &noopMailSender{}, testMFAConfig())
	ctx := claimsContext("test-user-id")

	if _, err := srv.DisableMFA(ctx, &authv1.DisableMFARequest{Password: testPassword}); err != nil {
		t.Fatalf("DisableMFA failed: %v", err)
	}

	ev := waitForAuditEvent(t, srv)
	if ev.EventType != db.AuditMFADisabled {
		t.Errorf("EventType = %q, want %q", ev.EventType, db.AuditMFADisabled)
	}
}

func TestVerifyMFA_EmitsAuditMFAVerified(t *testing.T) {
	mdb := &mockDB{
		getMFAChallengeFn: func(_ context.Context, tokenHash string) (*model.MFAChallenge, error) {
			ch := validChallenge()
			ch.TokenHash = tokenHash
			return ch, nil
		},
		getMFASecretFn: func(_ context.Context, _ string) (*db.MFAUser, error) {
			return &db.MFAUser{UserID: "test-user-id", Enabled: true, Secret: testMFASecret}, nil
		},
		getUserByIDFn: func(_ context.Context, _ string) (*model.UserInternal, error) {
			return testUser(), nil
		},
	}
	srv := newTestServerWithMFA(mdb, &noopMailSender{}, testMFAConfig())
	ctx := context.Background()

	if _, err := srv.VerifyMFA(ctx, &authv1.VerifyMFARequest{
		MfaToken: "raw-challenge-token",
		Code:     testMFACode(t, srv),
	}); err != nil {
		t.Fatalf("VerifyMFA failed: %v", err)
	}

	ev := waitForAuditEvent(t, srv)
	if ev.EventType != db.AuditMFAVerified {
		t.Errorf("EventType = %q, want %q", ev.EventType, db.AuditMFAVerified)
	}
}

func TestVerifyMFA_EmitsAuditMFAVerifyFailed(t *testing.T) {
	mdb := &mockDB{
		getMFAChallengeFn: func(_ context.Context, tokenHash string) (*model.MFAChallenge, error) {
			ch := validChallenge()
			ch.TokenHash = tokenHash
			return ch, nil
		},
		getMFASecretFn: func(_ context.Context, _ string) (*db.MFAUser, error) {
			return &db.MFAUser{UserID: "test-user-id", Enabled: true, Secret: testMFASecret}, nil
		},
	}
	srv := newTestServerWithMFA(mdb, &noopMailSender{}, testMFAConfig())
	ctx := context.Background()

	_, _ = srv.VerifyMFA(ctx, &authv1.VerifyMFARequest{
		MfaToken: "raw-challenge-token",
		Code:     "000000",
	})

	ev := waitForAuditEvent(t, srv)
	if ev.EventType != db.AuditMFAVerifyFailed {
		t.Errorf("EventType = %q, want %q", ev.EventType, db.AuditMFAVerifyFailed)
	}
	if ev.Metadata["reason"] != "invalid_code" {
		t.Errorf("Metadata[reason] = %v, want invalid_code", ev.Metadata["reason"])
	}
}

func TestGenerateBackupCodes_EmitsAuditMFABackupCodesGenerated(t *testing.T) {
	mdb := &mockDB{
		getUserByIDFn: func(_ context.Context, _ string) (*model.UserInternal, error) {
			return testUser(), nil
		},
		getMFAStatusFn: func(_ context.Context, _ string) (bool, error) {
			return true, nil
		},
		storeBackupCodeHashesFn: func(_ context.Context, _ string, _ []string) error {
			return nil
		},
	}
	srv := newTestServerWithMFA(mdb, &noopMailSender{}, testMFAConfig())
	ctx := claimsContext("test-user-id")

	if _, err := srv.GenerateBackupCodes(ctx, &authv1.GenerateBackupCodesRequest{Password: testPassword}); err != nil {
		t.Fatalf("GenerateBackupCodes failed: %v", err)
	}

	ev := waitForAuditEvent(t, srv)
	if ev.EventType != db.AuditMFABackupCodesGenerated {
		t.Errorf("EventType = %q, want %q", ev.EventType, db.AuditMFABackupCodesGenerated)
	}
}
