// mfa.go implements the TOTP second-factor (MFA) endpoints:
//
//   - SetupMFA / EnableMFA — enrollment: generate + store a secret (encrypted
//     at rest), verify one code, then issue the backup-code set
//   - DisableMFA / GetMFAStatus / GenerateBackupCodes — management
//   - VerifyMFA — completes a pending-login challenge (see authentication.go's
//     Login gate) with a TOTP code or single-use backup code, then issues the
//     token pair exactly like a successful Login
//
// Every management endpoint starts with checkMFAEnabled() and fails closed
// when the global switch (MFAConfig.Enabled) is off; the login flow instead
// simply bypasses the MFA step (see Login). The error prefixes below are a
// contract for the API gateway (mirroring ErrBreachedPasswordPrefix) — keep
// them stable.
//
// Security invariants:
//   - The plaintext TOTP secret is returned exactly once (SetupMFA) and is
//     encrypted at rest (internal/db.CreateMFASecret).
//   - Backup codes are shown in plaintext exactly once; only Argon2id hashes
//     are stored, and consumption is atomic single-use.
//   - Challenge tokens are 256-bit random values; only their SHA-256 hash is
//     stored, and a challenge dies after ChallengeMaxAttempts guesses or its
//     TTL. Failed verifications also count against the per-user "mfa"
//     throttle scope (security_throttle), bounding TOTP guessing even when an
//     attacker can loop successful password logins.

package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/yeqown/go-qrcode/v2"
	"github.com/yeqown/go-qrcode/writer/standard"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/swayrider/authservice/internal/db"
	"github.com/swayrider/authservice/internal/model"
	authv1 "github.com/swayrider/protos/auth/v1"
	"github.com/swayrider/swlib/crypto"
	log "github.com/swayrider/swlib/logger"
	"github.com/swayrider/swlib/security"
	"github.com/swayrider/swlib/totp"
)

// Fixed error prefixes — the API gateway matches on these (see
// Docs/AuthImprovement/multifactor/PLAN_02.md). Keep them stable.
const (
	ErrMFADisabledPrefix     = "mfa is disabled"            // global switch off
	ErrMFAAlreadySetupPrefix = "mfa is already enabled"     // EnableMFA on an enabled account
	ErrMFANotSetupPrefix     = "mfa is not set up"          // Enable/Disable without a secret row
	ErrInvalidMFACodePrefix  = "invalid authentication code" // TOTP/backup-code rejection
)

const (
	// mfaBackupCodeLength is the per-code character count: 8-char Crockford
	// base32 (unambiguous to type), per the MFA decision doc.
	mfaBackupCodeLength = 8

	// mfaQRBlockWidth / mfaQRBorder render a ~256px QR PNG for typical
	// otpauth URLs (version 5-6 symbols, 37-41 modules: 37*6 + 2*12 = 246px).
	mfaQRBlockWidth = 6
	mfaQRBorder     = 12
)

// checkMFAEnabled fails closed when the global MFA switch is off: every
// management endpoint returns FailedPrecondition. Login bypasses the MFA
// step instead of erroring (see Login).
func (s *AuthServer) checkMFAEnabled() error {
	if !s.mfa.Enabled {
		return status.Error(codes.FailedPrecondition, ErrMFADisabledPrefix)
	}
	return nil
}

// renderQRPNG renders otpauthURL as a ~256px PNG with medium error
// correction. The image is served as base64 in the SetupMFA response so a
// user can enroll from a second device that scans the code.
func renderQRPNG(otpauthURL string) ([]byte, error) {
	qrc, err := qrcode.NewWith(otpauthURL,
		qrcode.WithErrorCorrectionLevel(qrcode.ErrorCorrectionMedium))
	if err != nil {
		return nil, fmt.Errorf("failed to create QR code: %w", err)
	}
	var buf bytes.Buffer
	w := standard.NewWithWriter(nopWriteCloser{&buf},
		standard.WithBuiltinImageEncoder(standard.PNG_FORMAT),
		standard.WithQRWidth(mfaQRBlockWidth),
		standard.WithBorderWidth(mfaQRBorder))
	if err := qrc.Save(w); err != nil {
		return nil, fmt.Errorf("failed to render QR code: %w", err)
	}
	return buf.Bytes(), nil
}

// nopWriteCloser adapts a plain io.Writer to the io.WriteCloser the QR
// writer expects; the in-memory buffer needs no close semantics.
type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }

// SetupMFA starts TOTP enrollment: it generates a fresh secret (stored
// encrypted, not yet enabled), builds the otpauth URL, and returns the
// secret, the URL, and a server-rendered QR PNG of the URL. The secret is
// shown exactly once — the app displays it for manual entry into an
// authenticator app.
//
// Returns:
//   - codes.FailedPrecondition: MFA disabled globally, or already enabled
//   - codes.Unauthenticated: no valid claims
//   - codes.Internal: generation or storage failure
func (s *AuthServer) SetupMFA(
	ctx context.Context,
	req *authv1.SetupMFARequest,
) (*authv1.SetupMFAResponse, error) {
	lg := s.Logger().Derive(log.WithFunction("SetupMFA"))

	if err := s.checkMFAEnabled(); err != nil {
		return nil, err
	}

	user, err := s.getUserFromClaims(ctx)
	if err != nil {
		return nil, err
	}

	enabled, err := s.DB().GetMFAStatus(ctx, user.ID)
	if err != nil {
		lg.Errorf("SetupMFA: %v", err)
		return nil, status.Error(codes.Internal, "internal error")
	}
	if enabled {
		return nil, status.Error(codes.FailedPrecondition, ErrMFAAlreadySetupPrefix)
	}

	secret, err := totp.GenerateSecret(20)
	if err != nil {
		lg.Errorf("SetupMFA: %v", err)
		return nil, status.Error(codes.Internal, "internal error")
	}
	otpauthURL := totp.GenerateOTPAuthURL(secret, user.Email, "SwayRider")

	png, err := renderQRPNG(otpauthURL)
	if err != nil {
		lg.Errorf("SetupMFA: %v", err)
		return nil, status.Error(codes.Internal, "internal error")
	}

	if err := s.DB().CreateMFASecret(ctx, user.ID, secret); err != nil {
		lg.Errorf("SetupMFA: %v", err)
		return nil, status.Error(codes.Internal, "internal error")
	}

	s.auditMFASetupStarted(ctx, user.ID, user.Email)
	lg.Debugf("user %s started MFA setup", user.ID)

	return &authv1.SetupMFAResponse{
		Secret:      secret,
		OtpauthUrl:  otpauthURL,
		QrPngBase64: base64.StdEncoding.EncodeToString(png),
	}, nil
}

// EnableMFA completes enrollment: the user proves control of the secret
// stored by SetupMFA by presenting a valid TOTP code, then MFA is enabled
// and a fresh set of single-use backup codes is issued (plaintext, once).
//
// Returns:
//   - codes.FailedPrecondition: MFA disabled globally, already enabled, or no
//     pending secret (SetupMFA not called)
//   - codes.InvalidArgument: code does not match the secret
func (s *AuthServer) EnableMFA(
	ctx context.Context,
	req *authv1.EnableMFARequest,
) (*authv1.EnableMFAResponse, error) {
	lg := s.Logger().Derive(log.WithFunction("EnableMFA"))

	if err := s.checkMFAEnabled(); err != nil {
		return nil, err
	}

	user, err := s.getUserFromClaims(ctx)
	if err != nil {
		return nil, err
	}

	enabled, err := s.DB().GetMFAStatus(ctx, user.ID)
	if err != nil {
		lg.Errorf("EnableMFA: %v", err)
		return nil, status.Error(codes.Internal, "internal error")
	}
	if enabled {
		return nil, status.Error(codes.FailedPrecondition, ErrMFAAlreadySetupPrefix)
	}

	mfaUser, err := s.DB().GetMFASecret(ctx, user.ID)
	if err != nil {
		if errors.Is(err, db.ErrNoMFARecord) {
			return nil, status.Error(codes.FailedPrecondition, ErrMFANotSetupPrefix)
		}
		lg.Errorf("EnableMFA: %v", err)
		return nil, status.Error(codes.Internal, "internal error")
	}

	valid, err := totp.Validate(mfaUser.Secret, req.Code, time.Now(), s.mfa.totpConfig())
	if err != nil {
		lg.Errorf("EnableMFA: %v", err)
		return nil, status.Error(codes.Internal, "internal error")
	}
	if !valid {
		lg.Debugf("user %s submitted an invalid MFA enable code", user.ID)
		return nil, status.Error(codes.InvalidArgument, ErrInvalidMFACodePrefix)
	}

	if err := s.DB().EnableMFA(ctx, user.ID); err != nil {
		lg.Errorf("EnableMFA: %v", err)
		return nil, status.Error(codes.Internal, "internal error")
	}

	backupCodes, err := s.generateAndStoreBackupCodes(ctx, user.ID)
	if err != nil {
		lg.Errorf("EnableMFA: %v", err)
		return nil, status.Error(codes.Internal, "internal error")
	}

	s.auditMFAEnabled(ctx, user.ID, user.Email)
	s.auditMFABackupCodesGenerated(ctx, user.ID)
	lg.Debugf("user %s enabled MFA", user.ID)

	return &authv1.EnableMFAResponse{BackupCodes: backupCodes}, nil
}

// DisableMFA turns MFA off for the account: the enrollment row and all
// backup codes are deleted. The caller's password is required and verified
// against the stored hash; a mismatch returns a uniform "invalid password"
// (no enumeration signal).
//
// Returns:
//   - codes.FailedPrecondition: MFA disabled globally
//   - codes.Unauthenticated: no valid claims, or wrong password
func (s *AuthServer) DisableMFA(
	ctx context.Context,
	req *authv1.DisableMFARequest,
) (*authv1.DisableMFAResponse, error) {
	lg := s.Logger().Derive(log.WithFunction("DisableMFA"))

	if err := s.checkMFAEnabled(); err != nil {
		return nil, err
	}

	user, err := s.getUserFromClaims(ctx)
	if err != nil {
		return nil, err
	}

	if ok, err := s.verifyOwnPassword(user, req.Password); err != nil {
		return nil, err
	} else if !ok {
		lg.Debugf("user %s failed to disable MFA: invalid password", user.Email)
		return nil, status.Error(codes.Unauthenticated, "invalid password")
	}

	if err := s.DB().DisableMFA(ctx, user.ID); err != nil {
		lg.Errorf("DisableMFA: %v", err)
		return nil, status.Error(codes.Internal, "internal error")
	}

	s.auditMFADisabled(ctx, user.ID, user.Email)
	lg.Debugf("user %s disabled MFA", user.ID)

	return &authv1.DisableMFAResponse{}, nil
}

// GetMFAStatus reports whether the calling user has MFA enabled.
//
// Returns:
//   - codes.FailedPrecondition: MFA disabled globally
//   - codes.Unauthenticated: no valid claims
func (s *AuthServer) GetMFAStatus(
	ctx context.Context,
	req *authv1.GetMFAStatusRequest,
) (*authv1.GetMFAStatusResponse, error) {
	lg := s.Logger().Derive(log.WithFunction("GetMFAStatus"))

	if err := s.checkMFAEnabled(); err != nil {
		return nil, err
	}

	user, err := s.getUserFromClaims(ctx)
	if err != nil {
		return nil, err
	}

	enabled, err := s.DB().GetMFAStatus(ctx, user.ID)
	if err != nil {
		lg.Errorf("GetMFAStatus: %v", err)
		return nil, status.Error(codes.Internal, "internal error")
	}
	return &authv1.GetMFAStatusResponse{Enabled: enabled}, nil
}

// VerifyMFA completes a pending-login MFA challenge (issued by Login when
// the account has MFA enabled): the caller presents the challenge token plus
// a TOTP code or single-use backup code. On success the challenge is
// consumed and the normal token pair is issued, exactly like a completed
// Login (including the remember-me cookie preference). On failure the
// challenge's attempt counter and the per-user "mfa" throttle scope are both
// advanced; a challenge that exhausts ChallengeMaxAttempts is invalidated.
//
// This endpoint is public (no access token exists at this point in the flow).
//
// Returns:
//   - codes.Unauthenticated: unknown/expired challenge, locked MFA scope, or
//     invalid code (uniform message, anti-enumeration)
func (s *AuthServer) VerifyMFA(
	ctx context.Context,
	req *authv1.VerifyMFARequest,
) (*authv1.VerifyMFAResponse, error) {
	lg := s.Logger().Derive(log.WithFunction("VerifyMFA"))

	if err := s.checkMFAEnabled(); err != nil {
		return nil, err
	}

	tokenHash := model.HashToken(req.MfaToken)
	challenge, err := s.DB().GetMFAChallenge(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, db.ErrNoMFAChallengeFound) {
			lg.Debugf("MFA verify: unknown challenge token")
			s.auditMFAVerifyFailed(ctx, nil, "challenge_expired")
			return nil, status.Error(codes.Unauthenticated, "invalid or expired mfa token")
		}
		lg.Errorf("VerifyMFA: %v", err)
		return nil, status.Error(codes.Internal, "internal error")
	}
	if time.Now().After(challenge.ValidUntil) {
		lg.Debugf("MFA verify: expired challenge token")
		s.auditMFAVerifyFailed(ctx, &challenge.UserID, "challenge_expired")
		return nil, status.Error(codes.Unauthenticated, "invalid or expired mfa token")
	}

	// The "mfa" throttle scope is keyed per user, so an attacker who can
	// loop successful password logins still cannot guess TOTP codes without
	// bound.
	if s.isLocked(ctx, db.ScopeMFA, challenge.UserID) {
		lg.Debugf("MFA verify: user %s MFA scope is locked", challenge.UserID)
		s.auditMFAVerifyFailed(ctx, &challenge.UserID, "locked")
		return nil, status.Error(codes.Unauthenticated, ErrInvalidMFACodePrefix)
	}

	mfaUser, err := s.DB().GetMFASecret(ctx, challenge.UserID)
	if err != nil {
		if errors.Is(err, db.ErrNoMFARecord) {
			// Enrollment deleted mid-challenge: the challenge is useless.
			_ = s.DB().ConsumeMFAChallenge(ctx, tokenHash)
			s.auditMFAVerifyFailed(ctx, &challenge.UserID, "invalid_code")
			return nil, status.Error(codes.Unauthenticated, ErrInvalidMFACodePrefix)
		}
		lg.Errorf("VerifyMFA: %v", err)
		return nil, status.Error(codes.Internal, "internal error")
	}

	valid, err := totp.Validate(mfaUser.Secret, req.Code, time.Now(), s.mfa.totpConfig())
	if err != nil {
		lg.Errorf("VerifyMFA: %v", err)
		return nil, status.Error(codes.Internal, "internal error")
	}

	if !valid {
		lg.Debugf("MFA verify: invalid code for user %s", challenge.UserID)
		attempts, err := s.DB().IncrementMFAChallengeAttempts(ctx, tokenHash)
		if err != nil {
			// Challenge may already be gone; still record the throttle failure.
			lg.Warnf("VerifyMFA: %v", err)
		}
		if s.mfa.ChallengeMaxAttempts > 0 && attempts >= s.mfa.ChallengeMaxAttempts {
			if err := s.DB().ConsumeMFAChallenge(ctx, tokenHash); err != nil {
				lg.Warnf("VerifyMFA: %v", err)
			}
		}
		if _, err := s.DB().RecordAttemptResult(ctx, db.ScopeMFA, challenge.UserID, false,
			s.mfa.LockoutMaxAttempts, s.mfa.LockoutWindow, s.mfa.LockoutDuration); err != nil {
			lg.Warnf("VerifyMFA: %v", err)
		}
		s.auditMFAVerifyFailed(ctx, &challenge.UserID, "invalid_code")
		return nil, status.Error(codes.Unauthenticated, ErrInvalidMFACodePrefix)
	}

	// Success: invalidate the challenge, clear the throttle counter, and
	// issue the token pair exactly like Login.
	if err := s.DB().ConsumeMFAChallenge(ctx, tokenHash); err != nil {
		lg.Warnf("VerifyMFA: %v", err)
	}
	if _, err := s.DB().RecordAttemptResult(ctx, db.ScopeMFA, challenge.UserID, true,
		s.mfa.LockoutMaxAttempts, s.mfa.LockoutWindow, s.mfa.LockoutDuration); err != nil {
		lg.Warnf("VerifyMFA: %v", err)
	}

	user, err := s.DB().GetUserByID(ctx, challenge.UserID)
	if err != nil {
		lg.Errorf("VerifyMFA: %v", err)
		return nil, status.Error(codes.Unauthenticated, "invalid or expired mfa token")
	}

	origIp, _ := security.GetOrigIp(ctx)
	userAgent, _ := security.GetUserAgent(ctx)
	accessToken, refreshToken, err := s.createAuthTokens(ctx, user, model.FirstIP(origIp), userAgent)
	if err != nil {
		return nil, err
	}

	// The login response doesn't set remember-me on the pending branch (no
	// tokens yet), so VerifyMFA forwards the preference itself for the
	// cookie the CookieForwarder issues on this response.
	if err = grpc.SetHeader(ctx, metadata.Pairs(
		"remember-me", fmt.Sprintf("%v", req.RememberMe))); err != nil {
		lg.Warnf("failed to set remember-me header: %v", err)
	}

	s.auditMFAVerified(ctx, user.ID)
	lg.Debugf("user %s completed MFA verification", user.ID)

	return &authv1.VerifyMFAResponse{
		AccessToken:  string(accessToken),
		RefreshToken: refreshToken.Token,
	}, nil
}

// GenerateBackupCodes replaces the user's backup-code set with a fresh one
// (invalidating the previous set) and returns the new plaintext codes once.
// The caller's password is required.
//
// Returns:
//   - codes.FailedPrecondition: MFA disabled globally, or not enabled
//   - codes.Unauthenticated: no valid claims, or wrong password
func (s *AuthServer) GenerateBackupCodes(
	ctx context.Context,
	req *authv1.GenerateBackupCodesRequest,
) (*authv1.GenerateBackupCodesResponse, error) {
	lg := s.Logger().Derive(log.WithFunction("GenerateBackupCodes"))

	if err := s.checkMFAEnabled(); err != nil {
		return nil, err
	}

	user, err := s.getUserFromClaims(ctx)
	if err != nil {
		return nil, err
	}

	enabled, err := s.DB().GetMFAStatus(ctx, user.ID)
	if err != nil {
		lg.Errorf("GenerateBackupCodes: %v", err)
		return nil, status.Error(codes.Internal, "internal error")
	}
	if !enabled {
		return nil, status.Error(codes.FailedPrecondition, ErrMFANotSetupPrefix)
	}

	if ok, err := s.verifyOwnPassword(user, req.Password); err != nil {
		return nil, err
	} else if !ok {
		lg.Debugf("user %s failed to regenerate backup codes: invalid password", user.Email)
		return nil, status.Error(codes.Unauthenticated, "invalid password")
	}

	backupCodes, err := s.generateAndStoreBackupCodes(ctx, user.ID)
	if err != nil {
		lg.Errorf("GenerateBackupCodes: %v", err)
		return nil, status.Error(codes.Internal, "internal error")
	}

	s.auditMFABackupCodesGenerated(ctx, user.ID)
	lg.Debugf("user %s regenerated backup codes", user.ID)

	return &authv1.GenerateBackupCodesResponse{BackupCodes: backupCodes}, nil
}


// generateAndStoreBackupCodes generates a fresh backup-code set, hashes each
// code with Argon2id, and replaces the stored set. Returns the plaintext
// codes (shown to the user exactly once).
func (s *AuthServer) generateAndStoreBackupCodes(ctx context.Context, userID string) ([]string, error) {
	codes, err := totp.GenerateBackupCodes(s.mfa.BackupCodeCount, mfaBackupCodeLength)
	if err != nil {
		return nil, err
	}
	hashes := make([]string, 0, len(codes))
	for _, code := range codes {
		h, err := crypto.CalculatePasswordHash(code)
		if err != nil {
			return nil, err
		}
		hashes = append(hashes, h)
	}
	if err := s.DB().StoreBackupCodeHashes(ctx, userID, hashes); err != nil {
		return nil, err
	}
	return codes, nil
}

// createMFAChallenge issues a pending-login challenge for userID: a 256-bit
// random token is returned to the caller, and only its SHA-256 hash is
// stored, valid for MFAConfig.ChallengeTTL. One live challenge per user — a
// new login replaces the previous one.
func (s *AuthServer) createMFAChallenge(ctx context.Context, userID string) (string, error) {
	token, err := crypto.GenerateSecureRandomString(64)
	if err != nil {
		return "", fmt.Errorf("failed to generate MFA challenge token: %w", err)
	}
	if err := s.DB().CreateMFAChallenge(ctx, userID, model.HashToken(token),
		time.Now().Add(s.mfa.ChallengeTTL)); err != nil {
		return "", err
	}
	return token, nil
}

// verifyOwnPassword checks candidate against the user's stored Argon2id
// hash. A nil/errored verification is reported as "not ok" so callers can
// return the uniform "invalid password" response without distinguishing
// state errors from wrong passwords (no enumeration signal).
func (s *AuthServer) verifyOwnPassword(user *model.UserInternal, candidate string) (bool, error) {
	if !user.PasswordHash.Valid {
		s.Logger().Debugf("user %s has an invalid password state", user.Email)
		return false, nil
	}
	ok, err := crypto.VerifyPassword(user.PasswordHash.String, candidate)
	if err != nil {
		s.Logger().Debugf("user %s password verification error: %v", user.Email, err)
		return false, nil
	}
	return ok, nil
}

// normalizeBackupCode strips separators and whitespace and folds to upper
// case, so a code entered as "abcd-efgh", "abcd efgh" or "abcdEFGH" matches
// the stored hash of the uppercase code returned at issuance.
func normalizeBackupCode(code string) string {
	var b strings.Builder
	b.Grow(len(code))
	for _, r := range strings.ToUpper(code) {
		if (r >= '0' && r <= '9') || (r >= 'A' && r <= 'Z') {
			b.WriteRune(r)
		}
	}
	return b.String()
}
