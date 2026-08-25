package server

import (
	"context"
	"strings"
	"testing"

	"github.com/swayrider/authservice/internal/db"
	"github.com/swayrider/authservice/internal/model"
	authv1 "github.com/swayrider/protos/auth/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// =============================================================================
// RequestMfaReset Tests
// =============================================================================

func TestRequestMfaReset_Success(t *testing.T) {
	var consumedCode string
	mdb := &mockDB{
		getUserByEmailFn: func(_ context.Context, _ string) (*model.UserInternal, error) {
			return testUser(), nil
		},
		getMFAStatusFn: func(_ context.Context, _ string) (bool, error) {
			return true, nil
		},
		consumeBackupCodeFn: func(_ context.Context, userID, code string) (bool, error) {
			if userID != "test-user-id" {
				t.Errorf("ConsumeBackupCode userID = %q, want test-user-id", userID)
			}
			consumedCode = code
			return true, nil
		},
		createMFAResetTokenFn: func(_ context.Context, userID, pendingSecret string) (*model.MFAResetToken, error) {
			return &model.MFAResetToken{UserId: userID, PendingSecret: pendingSecret, Token: "test-mfa-reset-token"}, nil
		},
	}
	mail := newRecordingMailSender()
	srv := newTestServerWithMFA(mdb, mail, testMFAConfig())
	ctx := context.Background()

	// Input with lowercasing + separators must be normalized before the db
	// layer verifies it against the stored (uppercase) code, same as
	// VerifyMFA's former backup-code path.
	resp, err := srv.RequestMfaReset(ctx, &authv1.RequestMfaResetRequest{
		Email:      "test@example.com",
		Password:   testPassword,
		BackupCode: "abcd-1234",
	})
	if err != nil {
		t.Fatalf("RequestMfaReset failed: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if consumedCode != "ABCD1234" {
		t.Errorf("ConsumeBackupCode code = %q, want normalized %q", consumedCode, "ABCD1234")
	}
	mail.waitForSend(t)
}

func TestRequestMfaReset_InvalidBackupCode(t *testing.T) {
	// A wrong or already-used backup code must be rejected -- and must not
	// send the reset email -- even though email+password and MFA status
	// checked out.
	mdb := &mockDB{
		getUserByEmailFn: func(_ context.Context, _ string) (*model.UserInternal, error) {
			return testUser(), nil
		},
		getMFAStatusFn: func(_ context.Context, _ string) (bool, error) {
			return true, nil
		},
		consumeBackupCodeFn: func(_ context.Context, _, _ string) (bool, error) {
			return false, nil
		},
	}
	mail := newRecordingMailSender()
	srv := newTestServerWithMFA(mdb, mail, testMFAConfig())
	ctx := context.Background()

	_, err := srv.RequestMfaReset(ctx, &authv1.RequestMfaResetRequest{
		Email:      "test@example.com",
		Password:   testPassword,
		BackupCode: "WRONG123",
	})
	st, _ := status.FromError(err)
	if st.Code() != codes.Unauthenticated {
		t.Errorf("code = %v, want %v", st.Code(), codes.Unauthenticated)
	}
	if !strings.Contains(st.Message(), ErrInvalidMFACodePrefix) {
		t.Errorf("message = %q, want prefix %q", st.Message(), ErrInvalidMFACodePrefix)
	}
	mail.assertNoSend(t)
}

func TestRequestMfaReset_BackupCodeLockedScope_SkipsConsumption(t *testing.T) {
	consumeCalled := false
	mdb := &mockDB{
		getUserByEmailFn: func(_ context.Context, _ string) (*model.UserInternal, error) {
			return testUser(), nil
		},
		getMFAStatusFn: func(_ context.Context, _ string) (bool, error) {
			return true, nil
		},
		isAttemptLockedFn: func(_ context.Context, scope db.ThrottleScope, _ string) (bool, error) {
			return scope == db.ScopeMFA, nil
		},
		consumeBackupCodeFn: func(_ context.Context, _, _ string) (bool, error) {
			consumeCalled = true
			return true, nil
		},
	}
	mail := newRecordingMailSender()
	srv := newTestServerWithMFA(mdb, mail, testMFAConfig())
	ctx := context.Background()

	_, err := srv.RequestMfaReset(ctx, &authv1.RequestMfaResetRequest{
		Email:      "test@example.com",
		Password:   testPassword,
		BackupCode: "ABCD1234",
	})
	st, _ := status.FromError(err)
	if st.Code() != codes.Unauthenticated {
		t.Errorf("code = %v, want %v", st.Code(), codes.Unauthenticated)
	}
	if consumeCalled {
		t.Error("a locked mfa scope must short-circuit before consuming a backup code")
	}
	mail.assertNoSend(t)
}

func TestRequestMfaReset_WrongPassword(t *testing.T) {
	tokenCreated := false
	mdb := &mockDB{
		getUserByEmailFn: func(_ context.Context, _ string) (*model.UserInternal, error) {
			return testUser(), nil
		},
		createMFAResetTokenFn: func(_ context.Context, userID, pendingSecret string) (*model.MFAResetToken, error) {
			tokenCreated = true
			return &model.MFAResetToken{UserId: userID, PendingSecret: pendingSecret}, nil
		},
	}
	mail := newRecordingMailSender()
	srv := newTestServerWithMFA(mdb, mail, testMFAConfig())
	ctx := context.Background()

	_, err := srv.RequestMfaReset(ctx, &authv1.RequestMfaResetRequest{
		Email:    "test@example.com",
		Password: "wrong-password",
	})
	st, _ := status.FromError(err)
	if st.Code() != codes.Unauthenticated {
		t.Errorf("code = %v, want %v", st.Code(), codes.Unauthenticated)
	}
	if st.Message() != "invalid email or password" {
		t.Errorf("message = %q, want uniform %q", st.Message(), "invalid email or password")
	}
	if tokenCreated {
		t.Error("no MFA reset token must be created for a wrong password")
	}
	mail.assertNoSend(t)
}

func TestRequestMfaReset_UnknownEmail_SameUniformError(t *testing.T) {
	mdb := &mockDB{
		getUserByEmailFn: func(_ context.Context, _ string) (*model.UserInternal, error) {
			return nil, db.ErrUserNotFound
		},
	}
	srv := newTestServerWithMFA(mdb, &noopMailSender{}, testMFAConfig())
	ctx := context.Background()

	_, err := srv.RequestMfaReset(ctx, &authv1.RequestMfaResetRequest{
		Email:    "nobody@example.com",
		Password: testPassword,
	})
	st, _ := status.FromError(err)
	if st.Code() != codes.Unauthenticated {
		t.Errorf("code = %v, want %v", st.Code(), codes.Unauthenticated)
	}
	// Deliberately the exact same message as TestRequestMfaReset_WrongPassword
	// -- an unknown email must not be distinguishable from a known email with
	// the wrong password (anti-enumeration, mirroring Login).
	if st.Message() != "invalid email or password" {
		t.Errorf("message = %q, want uniform %q", st.Message(), "invalid email or password")
	}
}

func TestRequestMfaReset_MFANotEnabled(t *testing.T) {
	mdb := &mockDB{
		getUserByEmailFn: func(_ context.Context, _ string) (*model.UserInternal, error) {
			return testUser(), nil
		},
		getMFAStatusFn: func(_ context.Context, _ string) (bool, error) {
			return false, nil
		},
	}
	mail := newRecordingMailSender()
	srv := newTestServerWithMFA(mdb, mail, testMFAConfig())
	ctx := context.Background()

	_, err := srv.RequestMfaReset(ctx, &authv1.RequestMfaResetRequest{
		Email:    "test@example.com",
		Password: testPassword,
	})
	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition {
		t.Errorf("code = %v, want %v", st.Code(), codes.FailedPrecondition)
	}
	mail.assertNoSend(t)
}

func TestRequestMfaReset_GlobalSwitchOff(t *testing.T) {
	srv := newTestServer(&mockDB{}, &noopMailSender{})
	ctx := context.Background()

	_, err := srv.RequestMfaReset(ctx, &authv1.RequestMfaResetRequest{
		Email:    "test@example.com",
		Password: testPassword,
	})
	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition {
		t.Errorf("code = %v, want %v", st.Code(), codes.FailedPrecondition)
	}
}

func TestRequestMfaReset_LockedIdentifier_SkipsLookup(t *testing.T) {
	lookupCalled := false
	mdb := &mockDB{
		isAttemptLockedFn: func(_ context.Context, scope db.ThrottleScope, _ string) (bool, error) {
			return scope == db.ScopeLogin, nil
		},
		getUserByEmailFn: func(_ context.Context, _ string) (*model.UserInternal, error) {
			lookupCalled = true
			return testUser(), nil
		},
	}
	srv := newTestServerWithMFA(mdb, &noopMailSender{}, testMFAConfig())
	ctx := context.Background()

	_, err := srv.RequestMfaReset(ctx, &authv1.RequestMfaResetRequest{
		Email:    "test@example.com",
		Password: testPassword,
	})
	st, _ := status.FromError(err)
	if st.Code() != codes.Unauthenticated {
		t.Errorf("code = %v, want %v", st.Code(), codes.Unauthenticated)
	}
	if lookupCalled {
		t.Error("a locked identifier must short-circuit before any user lookup")
	}
}
