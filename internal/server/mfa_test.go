package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"image/png"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/swayrider/authservice/internal/db"
	"github.com/swayrider/authservice/internal/model"
	authv1 "github.com/swayrider/protos/auth/v1"
	"github.com/swayrider/swlib/totp"
)

// testMFAConfig returns a fully-enabled MFA configuration matching the
// production defaults (see cmd/authservice/main.go).
func testMFAConfig() MFAConfig {
	return MFAConfig{
		Enabled:              true,
		CodeLength:           6,
		TimeStep:             30 * time.Second,
		GracePeriod:          1,
		BackupCodeCount:      10,
		ChallengeTTL:         5 * time.Minute,
		ChallengeMaxAttempts: 5,
		LockoutMaxAttempts:   5,
		LockoutWindow:        15 * time.Minute,
		LockoutDuration:      15 * time.Minute,
	}
}

// testMFASecret is a fixed 32-char base32 secret (the RFC 6238 test seed
// "12345678901234567890") so TOTP codes are reproducible in tests.
const testMFASecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

func testMFACode(t *testing.T, srv *AuthServer) string {
	t.Helper()
	code, err := totp.GenerateCode(testMFASecret, time.Now(), srv.mfa.totpConfig())
	if err != nil {
		t.Fatalf("failed to generate TOTP code: %v", err)
	}
	return code
}

func validChallenge() *model.MFAChallenge {
	return &model.MFAChallenge{
		UserID:     "test-user-id",
		TokenHash:  model.HashToken("raw-challenge-token"),
		ValidUntil: time.Now().Add(5 * time.Minute),
	}
}

// =============================================================================
// SetupMFA Tests
// =============================================================================

func TestSetupMFA_Success(t *testing.T) {
	var storedSecret string
	mdb := &mockDB{
		getUserByIDFn: func(_ context.Context, _ string) (*model.UserInternal, error) {
			return testUser(), nil
		},
		getMFAStatusFn: func(_ context.Context, _ string) (bool, error) {
			return false, nil
		},
		createMFASecretFn: func(_ context.Context, userID, secret string) error {
			if userID != "test-user-id" {
				t.Errorf("CreateMFASecret userID = %q, want test-user-id", userID)
			}
			storedSecret = secret
			return nil
		},
	}
	srv := newTestServerWithMFA(mdb, &noopMailSender{}, testMFAConfig())
	ctx := claimsContext("test-user-id")

	resp, err := srv.SetupMFA(ctx, &authv1.SetupMFARequest{})
	if err != nil {
		t.Fatalf("SetupMFA failed: %v", err)
	}

	if len(resp.Secret) != 32 {
		t.Errorf("secret length = %d, want 32 (20 random bytes, unpadded base32)", len(resp.Secret))
	}
	if storedSecret != resp.Secret {
		t.Errorf("stored secret %q != returned secret %q (must be the same enrollment)", storedSecret, resp.Secret)
	}
	if !strings.HasPrefix(resp.OtpauthUrl, "otpauth://totp/") {
		t.Errorf("otpauth URL = %q, want otpauth://totp/ prefix", resp.OtpauthUrl)
	}
	if !strings.Contains(resp.OtpauthUrl, "secret="+resp.Secret) {
		t.Errorf("otpauth URL %q does not carry the generated secret", resp.OtpauthUrl)
	}

	pngBytes, err := base64.StdEncoding.DecodeString(resp.QrPngBase64)
	if err != nil {
		t.Fatalf("qr_png_base64 is not valid base64: %v", err)
	}
	img, err := png.Decode(bytes.NewReader(pngBytes))
	if err != nil {
		t.Fatalf("qr_png_base64 is not a decodable PNG: %v", err)
	}
	if size := img.Bounds().Dx(); size < 180 || size > 360 {
		t.Errorf("QR PNG width = %d, want ~256px", size)
	}
}

func TestSetupMFA_AlreadyEnabled(t *testing.T) {
	mdb := &mockDB{
		getUserByIDFn: func(_ context.Context, _ string) (*model.UserInternal, error) {
			return testUser(), nil
		},
		getMFAStatusFn: func(_ context.Context, _ string) (bool, error) {
			return true, nil
		},
	}
	srv := newTestServerWithMFA(mdb, &noopMailSender{}, testMFAConfig())
	ctx := claimsContext("test-user-id")

	_, err := srv.SetupMFA(ctx, &authv1.SetupMFARequest{})
	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition {
		t.Errorf("code = %v, want %v", st.Code(), codes.FailedPrecondition)
	}
	if !strings.Contains(st.Message(), ErrMFAAlreadySetupPrefix) {
		t.Errorf("message = %q, want prefix %q", st.Message(), ErrMFAAlreadySetupPrefix)
	}
}

func TestSetupMFA_GlobalSwitchOff(t *testing.T) {
	// Zero-value MFAConfig (newTestServer) has Enabled=false: management
	// endpoints fail closed.
	mdb := &mockDB{
		getUserByIDFn: func(_ context.Context, _ string) (*model.UserInternal, error) {
			return testUser(), nil
		},
	}
	srv := newTestServer(mdb, &noopMailSender{})
	ctx := claimsContext("test-user-id")

	_, err := srv.SetupMFA(ctx, &authv1.SetupMFARequest{})
	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition {
		t.Errorf("code = %v, want %v", st.Code(), codes.FailedPrecondition)
	}
	if !strings.Contains(st.Message(), ErrMFADisabledPrefix) {
		t.Errorf("message = %q, want prefix %q", st.Message(), ErrMFADisabledPrefix)
	}
}

// =============================================================================
// EnableMFA Tests
// =============================================================================

func TestEnableMFA_ValidCode(t *testing.T) {
	enabledCalled := false
	var storedHashes []string
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
		enableMFAFn: func(_ context.Context, userID string) error {
			enabledCalled = true
			if userID != "test-user-id" {
				t.Errorf("EnableMFA userID = %q, want test-user-id", userID)
			}
			return nil
		},
		storeBackupCodeHashesFn: func(_ context.Context, _ string, hashes []string) error {
			storedHashes = hashes
			return nil
		},
	}
	srv := newTestServerWithMFA(mdb, &noopMailSender{}, testMFAConfig())
	ctx := claimsContext("test-user-id")

	resp, err := srv.EnableMFA(ctx, &authv1.EnableMFARequest{Code: testMFACode(t, srv)})
	if err != nil {
		t.Fatalf("EnableMFA failed: %v", err)
	}
	if !enabledCalled {
		t.Error("EnableMFA must call the db EnableMFA on a valid code")
	}
	if len(resp.BackupCodes) != testMFAConfig().BackupCodeCount {
		t.Errorf("backup codes = %d, want %d", len(resp.BackupCodes), testMFAConfig().BackupCodeCount)
	}
	if len(storedHashes) != len(resp.BackupCodes) {
		t.Fatalf("stored hashes = %d, want %d", len(storedHashes), len(resp.BackupCodes))
	}
	const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	for i, code := range resp.BackupCodes {
		if len(code) != 8 {
			t.Errorf("backup code %d length = %d, want 8", i, len(code))
		}
		for _, r := range code {
			if !strings.ContainsRune(crockford, r) {
				t.Errorf("backup code %d contains %q, not in Crockford alphabet", i, r)
			}
		}
	}
	// Only hashes are persisted, never the plaintext codes.
	for i, h := range storedHashes {
		if h == resp.BackupCodes[i] {
			t.Errorf("stored hash %d equals the plaintext code", i)
		}
	}
}

func TestEnableMFA_InvalidCode(t *testing.T) {
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
	}
	srv := newTestServerWithMFA(mdb, &noopMailSender{}, testMFAConfig())
	ctx := claimsContext("test-user-id")

	_, err := srv.EnableMFA(ctx, &authv1.EnableMFARequest{Code: "000000"})
	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("code = %v, want %v", st.Code(), codes.InvalidArgument)
	}
	if !strings.Contains(st.Message(), ErrInvalidMFACodePrefix) {
		t.Errorf("message = %q, want prefix %q", st.Message(), ErrInvalidMFACodePrefix)
	}
}

func TestEnableMFA_NoSecretRow(t *testing.T) {
	mdb := &mockDB{
		getUserByIDFn: func(_ context.Context, _ string) (*model.UserInternal, error) {
			return testUser(), nil
		},
		getMFAStatusFn: func(_ context.Context, _ string) (bool, error) {
			return false, nil
		},
		getMFASecretFn: func(_ context.Context, _ string) (*db.MFAUser, error) {
			return nil, db.ErrNoMFARecord
		},
	}
	srv := newTestServerWithMFA(mdb, &noopMailSender{}, testMFAConfig())
	ctx := claimsContext("test-user-id")

	_, err := srv.EnableMFA(ctx, &authv1.EnableMFARequest{Code: "123456"})
	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition {
		t.Errorf("code = %v, want %v", st.Code(), codes.FailedPrecondition)
	}
	if !strings.Contains(st.Message(), ErrMFANotSetupPrefix) {
		t.Errorf("message = %q, want prefix %q", st.Message(), ErrMFANotSetupPrefix)
	}
}

func TestEnableMFA_AlreadyEnabled(t *testing.T) {
	mdb := &mockDB{
		getUserByIDFn: func(_ context.Context, _ string) (*model.UserInternal, error) {
			return testUser(), nil
		},
		getMFAStatusFn: func(_ context.Context, _ string) (bool, error) {
			return true, nil
		},
	}
	srv := newTestServerWithMFA(mdb, &noopMailSender{}, testMFAConfig())
	ctx := claimsContext("test-user-id")

	_, err := srv.EnableMFA(ctx, &authv1.EnableMFARequest{Code: "123456"})
	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition {
		t.Errorf("code = %v, want %v", st.Code(), codes.FailedPrecondition)
	}
	if !strings.Contains(st.Message(), ErrMFAAlreadySetupPrefix) {
		t.Errorf("message = %q, want prefix %q", st.Message(), ErrMFAAlreadySetupPrefix)
	}
}

// =============================================================================
// DisableMFA Tests
// =============================================================================

func TestDisableMFA_WrongPassword(t *testing.T) {
	disableCalled := false
	mdb := &mockDB{
		getUserByIDFn: func(_ context.Context, _ string) (*model.UserInternal, error) {
			return testUser(), nil
		},
		disableMFAFn: func(_ context.Context, _ string) error {
			disableCalled = true
			return nil
		},
	}
	srv := newTestServerWithMFA(mdb, &noopMailSender{}, testMFAConfig())
	ctx := claimsContext("test-user-id")

	_, err := srv.DisableMFA(ctx, &authv1.DisableMFARequest{Password: "wrong-password"})
	st, _ := status.FromError(err)
	if st.Code() != codes.Unauthenticated {
		t.Errorf("code = %v, want %v", st.Code(), codes.Unauthenticated)
	}
	if st.Message() != "invalid password" {
		t.Errorf("message = %q, want uniform %q", st.Message(), "invalid password")
	}
	if disableCalled {
		t.Error("DisableMFA must not be called with the wrong password")
	}
}

func TestDisableMFA_Success(t *testing.T) {
	var disabledUserID string
	mdb := &mockDB{
		getUserByIDFn: func(_ context.Context, _ string) (*model.UserInternal, error) {
			return testUser(), nil
		},
		disableMFAFn: func(_ context.Context, userID string) error {
			disabledUserID = userID
			return nil
		},
	}
	srv := newTestServerWithMFA(mdb, &noopMailSender{}, testMFAConfig())
	ctx := claimsContext("test-user-id")

	if _, err := srv.DisableMFA(ctx, &authv1.DisableMFARequest{Password: testPassword}); err != nil {
		t.Fatalf("DisableMFA failed: %v", err)
	}
	if disabledUserID != "test-user-id" {
		t.Errorf("DisableMFA called with %q, want test-user-id", disabledUserID)
	}
}

// =============================================================================
// GetMFAStatus Tests
// =============================================================================

func TestGetMFAStatus_Enabled(t *testing.T) {
	mdb := &mockDB{
		getUserByIDFn: func(_ context.Context, _ string) (*model.UserInternal, error) {
			return testUser(), nil
		},
		getMFAStatusFn: func(_ context.Context, _ string) (bool, error) {
			return true, nil
		},
	}
	srv := newTestServerWithMFA(mdb, &noopMailSender{}, testMFAConfig())
	ctx := claimsContext("test-user-id")

	resp, err := srv.GetMFAStatus(ctx, &authv1.GetMFAStatusRequest{})
	if err != nil {
		t.Fatalf("GetMFAStatus failed: %v", err)
	}
	if !resp.Enabled {
		t.Error("Enabled = false, want true")
	}
}

func TestGetMFAStatus_Disabled_WhenNoRow(t *testing.T) {
	mdb := &mockDB{
		getUserByIDFn: func(_ context.Context, _ string) (*model.UserInternal, error) {
			return testUser(), nil
		},
		getMFAStatusFn: func(_ context.Context, _ string) (bool, error) {
			return false, nil
		},
	}
	srv := newTestServerWithMFA(mdb, &noopMailSender{}, testMFAConfig())
	ctx := claimsContext("test-user-id")

	resp, err := srv.GetMFAStatus(ctx, &authv1.GetMFAStatusRequest{})
	if err != nil {
		t.Fatalf("GetMFAStatus failed: %v", err)
	}
	if resp.Enabled {
		t.Error("Enabled = true, want false")
	}
}

// =============================================================================
// VerifyMFA Tests
// =============================================================================

func TestVerifyMFA_ValidTOTP(t *testing.T) {
	challengeConsumed := false
	var recordedSuccess *bool
	var refreshTokenStored bool
	mdb := &mockDB{
		getMFAChallengeFn: func(_ context.Context, tokenHash string) (*model.MFAChallenge, error) {
			ch := validChallenge()
			ch.TokenHash = tokenHash
			return ch, nil
		},
		isAttemptLockedFn: func(_ context.Context, scope db.ThrottleScope, _ string) (bool, error) {
			if scope != db.ScopeMFA {
				t.Errorf("scope = %v, want %v", scope, db.ScopeMFA)
			}
			return false, nil
		},
		getMFASecretFn: func(_ context.Context, _ string) (*db.MFAUser, error) {
			return &db.MFAUser{UserID: "test-user-id", Enabled: true, Secret: testMFASecret}, nil
		},
		consumeMFAChallengeFn: func(_ context.Context, _ string) error {
			challengeConsumed = true
			return nil
		},
		recordAttemptResultFn: func(_ context.Context, scope db.ThrottleScope, _ string, success bool, _ int, _, _ time.Duration) (bool, error) {
			if scope != db.ScopeMFA {
				t.Errorf("scope = %v, want %v", scope, db.ScopeMFA)
			}
			recordedSuccess = &success
			return false, nil
		},
		getUserByIDFn: func(_ context.Context, _ string) (*model.UserInternal, error) {
			return testUser(), nil
		},
		createRefreshTokenFn: func(_ context.Context, _ *model.User, _, _, _ string) (*model.RefreshToken, error) {
			refreshTokenStored = true
			return &model.RefreshToken{Token: "mfa-refresh-token", UserId: "test-user-id",
				ValidUntil: time.Now().Add(30 * 24 * time.Hour)}, nil
		},
	}
	srv := newTestServerWithMFA(mdb, &noopMailSender{}, testMFAConfig())
	ctx := context.Background()

	resp, err := srv.VerifyMFA(ctx, &authv1.VerifyMFARequest{
		MfaToken: "raw-challenge-token",
		Code:     testMFACode(t, srv),
	})
	if err != nil {
		t.Fatalf("VerifyMFA failed: %v", err)
	}
	if resp.AccessToken == "" || resp.RefreshToken == "" {
		t.Error("expected a token pair on successful verification")
	}
	if !challengeConsumed {
		t.Error("challenge must be consumed on success (single-use)")
	}
	if !refreshTokenStored {
		t.Error("expected a refresh token to be stored, exactly like Login")
	}
	if recordedSuccess == nil || !*recordedSuccess {
		t.Error("expected RecordAttemptResult(success=true) to clear the MFA throttle counter")
	}
}

func TestVerifyMFA_ValidBackupCode(t *testing.T) {
	var consumedCode string
	mdb := &mockDB{
		getMFAChallengeFn: func(_ context.Context, tokenHash string) (*model.MFAChallenge, error) {
			ch := validChallenge()
			ch.TokenHash = tokenHash
			return ch, nil
		},
		isAttemptLockedFn: func(_ context.Context, _ db.ThrottleScope, _ string) (bool, error) {
			return false, nil
		},
		getMFASecretFn: func(_ context.Context, _ string) (*db.MFAUser, error) {
			return &db.MFAUser{UserID: "test-user-id", Enabled: true, Secret: testMFASecret}, nil
		},
		consumeBackupCodeFn: func(_ context.Context, userID, code string) (bool, error) {
			if userID != "test-user-id" {
				t.Errorf("ConsumeBackupCode userID = %q, want test-user-id", userID)
			}
			consumedCode = code
			return true, nil
		},
		getUserByIDFn: func(_ context.Context, _ string) (*model.UserInternal, error) {
			return testUser(), nil
		},
	}
	srv := newTestServerWithMFA(mdb, &noopMailSender{}, testMFAConfig())
	ctx := context.Background()

	// Input with lowercasing + separators must be normalized before the db
	// layer verifies it against the stored (uppercase) code.
	resp, err := srv.VerifyMFA(ctx, &authv1.VerifyMFARequest{
		MfaToken: "raw-challenge-token",
		Code:     "abcd-1234",
	})
	if err != nil {
		t.Fatalf("VerifyMFA failed: %v", err)
	}
	if resp.AccessToken == "" || resp.RefreshToken == "" {
		t.Error("expected a token pair on successful backup-code verification")
	}
	if consumedCode != "ABCD1234" {
		t.Errorf("ConsumeBackupCode code = %q, want normalized %q", consumedCode, "ABCD1234")
	}
}

func TestVerifyMFA_UsedBackupCodeFails(t *testing.T) {
	// A backup code that was already consumed reports false and must be
	// treated exactly like an invalid code (single-use enforcement).
	mdb := &mockDB{
		getMFAChallengeFn: func(_ context.Context, tokenHash string) (*model.MFAChallenge, error) {
			ch := validChallenge()
			ch.TokenHash = tokenHash
			return ch, nil
		},
		isAttemptLockedFn: func(_ context.Context, _ db.ThrottleScope, _ string) (bool, error) {
			return false, nil
		},
		getMFASecretFn: func(_ context.Context, _ string) (*db.MFAUser, error) {
			return &db.MFAUser{UserID: "test-user-id", Enabled: true, Secret: testMFASecret}, nil
		},
		consumeBackupCodeFn: func(_ context.Context, _, _ string) (bool, error) {
			return false, nil
		},
	}
	srv := newTestServerWithMFA(mdb, &noopMailSender{}, testMFAConfig())
	ctx := context.Background()

	_, err := srv.VerifyMFA(ctx, &authv1.VerifyMFARequest{
		MfaToken: "raw-challenge-token",
		Code:     "ABCD1234",
	})
	st, _ := status.FromError(err)
	if st.Code() != codes.Unauthenticated {
		t.Errorf("code = %v, want %v", st.Code(), codes.Unauthenticated)
	}
	if !strings.Contains(st.Message(), ErrInvalidMFACodePrefix) {
		t.Errorf("message = %q, want prefix %q", st.Message(), ErrInvalidMFACodePrefix)
	}
}

func TestVerifyMFA_UnknownChallenge(t *testing.T) {
	mdb := &mockDB{
		getMFAChallengeFn: func(_ context.Context, _ string) (*model.MFAChallenge, error) {
			return nil, db.ErrNoMFAChallengeFound
		},
	}
	srv := newTestServerWithMFA(mdb, &noopMailSender{}, testMFAConfig())
	ctx := context.Background()

	_, err := srv.VerifyMFA(ctx, &authv1.VerifyMFARequest{
		MfaToken: "bogus-token",
		Code:     "123456",
	})
	st, _ := status.FromError(err)
	if st.Code() != codes.Unauthenticated {
		t.Errorf("code = %v, want %v", st.Code(), codes.Unauthenticated)
	}
	if st.Message() != "invalid or expired mfa token" {
		t.Errorf("message = %q, want %q", st.Message(), "invalid or expired mfa token")
	}
}

func TestVerifyMFA_ExpiredChallenge(t *testing.T) {
	mdb := &mockDB{
		getMFAChallengeFn: func(_ context.Context, _ string) (*model.MFAChallenge, error) {
			ch := validChallenge()
			ch.ValidUntil = time.Now().Add(-time.Minute)
			return ch, nil
		},
	}
	srv := newTestServerWithMFA(mdb, &noopMailSender{}, testMFAConfig())
	ctx := context.Background()

	_, err := srv.VerifyMFA(ctx, &authv1.VerifyMFARequest{
		MfaToken: "raw-challenge-token",
		Code:     "123456",
	})
	st, _ := status.FromError(err)
	if st.Code() != codes.Unauthenticated {
		t.Errorf("code = %v, want %v", st.Code(), codes.Unauthenticated)
	}
	if st.Message() != "invalid or expired mfa token" {
		t.Errorf("message = %q, want %q", st.Message(), "invalid or expired mfa token")
	}
}

func TestVerifyMFA_AttemptsReachMax_ConsumesChallenge(t *testing.T) {
	challengeConsumed := false
	var recordedFailure *bool
	mdb := &mockDB{
		getMFAChallengeFn: func(_ context.Context, tokenHash string) (*model.MFAChallenge, error) {
			ch := validChallenge()
			ch.TokenHash = tokenHash
			return ch, nil
		},
		isAttemptLockedFn: func(_ context.Context, _ db.ThrottleScope, _ string) (bool, error) {
			return false, nil
		},
		getMFASecretFn: func(_ context.Context, _ string) (*db.MFAUser, error) {
			return &db.MFAUser{UserID: "test-user-id", Enabled: true, Secret: testMFASecret}, nil
		},
		incrementMFAChallengeAttemptsFn: func(_ context.Context, _ string) (int, error) {
			return testMFAConfig().ChallengeMaxAttempts, nil
		},
		consumeMFAChallengeFn: func(_ context.Context, _ string) error {
			challengeConsumed = true
			return nil
		},
		recordAttemptResultFn: func(_ context.Context, _ db.ThrottleScope, _ string, success bool, _ int, _, _ time.Duration) (bool, error) {
			recordedFailure = &success
			return false, nil
		},
	}
	srv := newTestServerWithMFA(mdb, &noopMailSender{}, testMFAConfig())
	ctx := context.Background()

	_, err := srv.VerifyMFA(ctx, &authv1.VerifyMFARequest{
		MfaToken: "raw-challenge-token",
		Code:     "000000",
	})
	st, _ := status.FromError(err)
	if st.Code() != codes.Unauthenticated {
		t.Errorf("code = %v, want %v", st.Code(), codes.Unauthenticated)
	}
	if !challengeConsumed {
		t.Error("challenge must be consumed once the attempt cap is reached")
	}
	if recordedFailure == nil || *recordedFailure {
		t.Error("expected RecordAttemptResult(success=false) for the throttle scope")
	}
}

func TestVerifyMFA_LockedScope(t *testing.T) {
	secretLookupCalled := false
	mdb := &mockDB{
		getMFAChallengeFn: func(_ context.Context, _ string) (*model.MFAChallenge, error) {
			return validChallenge(), nil
		},
		isAttemptLockedFn: func(_ context.Context, _ db.ThrottleScope, _ string) (bool, error) {
			return true, nil
		},
		getMFASecretFn: func(_ context.Context, _ string) (*db.MFAUser, error) {
			secretLookupCalled = true
			return nil, db.ErrNoMFARecord
		},
	}
	srv := newTestServerWithMFA(mdb, &noopMailSender{}, testMFAConfig())
	ctx := context.Background()

	_, err := srv.VerifyMFA(ctx, &authv1.VerifyMFARequest{
		MfaToken: "raw-challenge-token",
		Code:     "123456",
	})
	st, _ := status.FromError(err)
	if st.Code() != codes.Unauthenticated {
		t.Errorf("code = %v, want %v", st.Code(), codes.Unauthenticated)
	}
	if !strings.Contains(st.Message(), ErrInvalidMFACodePrefix) {
		t.Errorf("message = %q, want prefix %q", st.Message(), ErrInvalidMFACodePrefix)
	}
	if secretLookupCalled {
		t.Error("locked scope must be rejected before the secret is even loaded")
	}
}

func TestVerifyMFA_GlobalSwitchOff(t *testing.T) {
	mdb := &mockDB{}
	srv := newTestServer(mdb, &noopMailSender{})
	ctx := context.Background()

	_, err := srv.VerifyMFA(ctx, &authv1.VerifyMFARequest{MfaToken: "x", Code: "123456"})
	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition {
		t.Errorf("code = %v, want %v", st.Code(), codes.FailedPrecondition)
	}
	if !strings.Contains(st.Message(), ErrMFADisabledPrefix) {
		t.Errorf("message = %q, want prefix %q", st.Message(), ErrMFADisabledPrefix)
	}
}

// =============================================================================
// GenerateBackupCodes Tests
// =============================================================================

func TestGenerateBackupCodes_ReplacesOldSet(t *testing.T) {
	var storedHashes []string
	mdb := &mockDB{
		getUserByIDFn: func(_ context.Context, _ string) (*model.UserInternal, error) {
			return testUser(), nil
		},
		getMFAStatusFn: func(_ context.Context, _ string) (bool, error) {
			return true, nil
		},
		storeBackupCodeHashesFn: func(_ context.Context, _ string, hashes []string) error {
			storedHashes = hashes
			return nil
		},
	}
	srv := newTestServerWithMFA(mdb, &noopMailSender{}, testMFAConfig())
	ctx := claimsContext("test-user-id")

	resp, err := srv.GenerateBackupCodes(ctx, &authv1.GenerateBackupCodesRequest{Password: testPassword})
	if err != nil {
		t.Fatalf("GenerateBackupCodes failed: %v", err)
	}
	if len(resp.BackupCodes) != testMFAConfig().BackupCodeCount {
		t.Errorf("backup codes = %d, want %d", len(resp.BackupCodes), testMFAConfig().BackupCodeCount)
	}
	if len(storedHashes) != len(resp.BackupCodes) {
		t.Fatalf("stored hashes = %d, want %d (StoreBackupCodeHashes replaces the old set)", len(storedHashes), len(resp.BackupCodes))
	}
	for i, code := range resp.BackupCodes {
		if len(code) != 8 {
			t.Errorf("backup code %d length = %d, want 8", i, len(code))
		}
	}
}

func TestGenerateBackupCodes_NotEnabled(t *testing.T) {
	mdb := &mockDB{
		getUserByIDFn: func(_ context.Context, _ string) (*model.UserInternal, error) {
			return testUser(), nil
		},
		getMFAStatusFn: func(_ context.Context, _ string) (bool, error) {
			return false, nil
		},
	}
	srv := newTestServerWithMFA(mdb, &noopMailSender{}, testMFAConfig())
	ctx := claimsContext("test-user-id")

	_, err := srv.GenerateBackupCodes(ctx, &authv1.GenerateBackupCodesRequest{Password: testPassword})
	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition {
		t.Errorf("code = %v, want %v", st.Code(), codes.FailedPrecondition)
	}
	if !strings.Contains(st.Message(), ErrMFANotSetupPrefix) {
		t.Errorf("message = %q, want prefix %q", st.Message(), ErrMFANotSetupPrefix)
	}
}

func TestGenerateBackupCodes_WrongPassword(t *testing.T) {
	storeCalled := false
	mdb := &mockDB{
		getUserByIDFn: func(_ context.Context, _ string) (*model.UserInternal, error) {
			return testUser(), nil
		},
		getMFAStatusFn: func(_ context.Context, _ string) (bool, error) {
			return true, nil
		},
		storeBackupCodeHashesFn: func(_ context.Context, _ string, _ []string) error {
			storeCalled = true
			return nil
		},
	}
	srv := newTestServerWithMFA(mdb, &noopMailSender{}, testMFAConfig())
	ctx := claimsContext("test-user-id")

	_, err := srv.GenerateBackupCodes(ctx, &authv1.GenerateBackupCodesRequest{Password: "wrong-password"})
	st, _ := status.FromError(err)
	if st.Code() != codes.Unauthenticated {
		t.Errorf("code = %v, want %v", st.Code(), codes.Unauthenticated)
	}
	if st.Message() != "invalid password" {
		t.Errorf("message = %q, want uniform %q", st.Message(), "invalid password")
	}
	if storeCalled {
		t.Error("backup codes must not be regenerated with the wrong password")
	}
}

// =============================================================================
// normalizeBackupCode Tests
// =============================================================================

func TestNormalizeBackupCode(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"ABCD1234", "ABCD1234"},
		{"abcd1234", "ABCD1234"},
		{"abcd-1234", "ABCD1234"},
		{"abcd efgh", "ABCDEFGH"},
		{" a1b2 c3d4 ", "A1B2C3D4"},
		{"", ""},
		{"!!!", ""},
	}
	for _, tt := range tests {
		if got := normalizeBackupCode(tt.in); got != tt.want {
			t.Errorf("normalizeBackupCode(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
