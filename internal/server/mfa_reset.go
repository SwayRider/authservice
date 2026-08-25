// mfa_reset.go implements the email-verified MFA/TOTP reset flow.
//
// This is for a user who has lost their authenticator device (as opposed to
// just running low on backup codes): resetting the TOTP secret requires
// proving both something you know (password) and something you control (the
// registered inbox), and the old secret/backup codes stay valid the entire
// time -- there is no window where the account has no working second factor.
//
// The flow:
//  1. RequestMfaReset verifies email+password (same protection as Login) and
//     MFA being enabled, then emails a reset link carrying a fresh,
//     not-yet-active TOTP secret.
//  2. The user opens the link on any device -- since the app has no
//     deep-linking yet, this lands on authservice's own web page
//     (internal/web/reset_mfa.go), which shows a QR/manual key for the
//     pending secret and asks for one confirmation code.
//  3. On a valid code, the web handler atomically replaces the active
//     secret (internal/db.ReplaceMFASecret) and issues a fresh backup-code
//     set, shown once.

package server

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/swayrider/authservice/internal/db"
	"github.com/swayrider/authservice/internal/model"
	"github.com/swayrider/authservice/internal/svctoken"
	"github.com/swayrider/grpcclients/mailclient"
	authv1 "github.com/swayrider/protos/auth/v1"
	"github.com/swayrider/swlib/crypto"
	log "github.com/swayrider/swlib/logger"
	"github.com/swayrider/swlib/security"
	"github.com/swayrider/swlib/totp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// RequestMfaReset verifies the caller's credentials and, if the account has
// MFA enabled, emails a reset link asynchronously.
//
// Credential verification mirrors Login exactly (same db.ScopeLogin lockout,
// same uniform "invalid email or password" error on any mismatch): this
// endpoint is effectively a partial re-login, so it must not open a second,
// weaker password-guessing path. Only after credentials check out does it
// diverge -- an account with no MFA enrollment has nothing to reset, and
// that response is allowed to be specific since identity is already proven.
func (s *AuthServer) RequestMfaReset(
	ctx context.Context,
	req *authv1.RequestMfaResetRequest,
) (*authv1.RequestMfaResetResponse, error) {
	lg := s.Logger().Derive(log.WithFunction("RequestMfaReset"))

	if err := s.checkMFAEnabled(); err != nil {
		return nil, err
	}

	identifier := normalizeIdentifier(req.Email)

	if s.isLocked(ctx, db.ScopeLogin, identifier) {
		return nil, status.Error(codes.Unauthenticated, "invalid email or password")
	}

	u, err := s.DB().GetUserByEmail(ctx, req.Email)
	if err != nil {
		lg.Debugf("MFA reset request for %s failed: %v", req.Email, err)
		if errors.Is(err, db.ErrUserNotFound) {
			s.recordLoginAttempt(ctx, identifier, false)
			return nil, status.Error(codes.Unauthenticated, "invalid email or password")
		}
		return nil, status.Error(codes.Internal, "internal error")
	}

	if !u.PasswordHash.Valid {
		s.recordLoginAttempt(ctx, identifier, false)
		return nil, status.Error(codes.Unauthenticated, "invalid email or password")
	}

	passwordOk, err := crypto.VerifyPassword(u.PasswordHash.String, req.Password)
	if err != nil || !passwordOk {
		lg.Debugf("MFA reset request for %s failed: invalid password", req.Email)
		s.recordLoginAttempt(ctx, identifier, false)
		return nil, status.Error(codes.Unauthenticated, "invalid email or password")
	}

	s.recordLoginAttempt(ctx, identifier, true)

	enabled, err := s.DB().GetMFAStatus(ctx, u.ID)
	if err != nil {
		lg.Errorf("RequestMfaReset: %v", err)
		return nil, status.Error(codes.Internal, "internal error")
	}
	if !enabled {
		return nil, status.Error(codes.FailedPrecondition, ErrMFANotSetupPrefix)
	}

	// A reset is only ever completed with a backup code -- there is no
	// direct backup-code login (see VerifyMFA). This is safe to check as a
	// distinct error from the email/password check above: reaching this
	// point already required correct credentials, so it isn't an
	// enumeration signal. Guarded by the same "mfa" throttle scope used for
	// login-time TOTP/backup-code guessing.
	if s.isLocked(ctx, db.ScopeMFA, u.ID) {
		return nil, status.Error(codes.Unauthenticated, ErrInvalidMFACodePrefix)
	}
	claimed, err := s.DB().ConsumeBackupCode(ctx, u.ID, normalizeBackupCode(req.BackupCode))
	if err != nil {
		lg.Errorf("RequestMfaReset: %v", err)
		return nil, status.Error(codes.Internal, "internal error")
	}
	if _, err := s.DB().RecordAttemptResult(ctx, db.ScopeMFA, u.ID, claimed,
		s.mfa.LockoutMaxAttempts, s.mfa.LockoutWindow, s.mfa.LockoutDuration); err != nil {
		lg.Warnf("RequestMfaReset: %v", err)
	}
	if !claimed {
		lg.Debugf("MFA reset request for %s failed: invalid backup code", req.Email)
		return nil, status.Error(codes.Unauthenticated, ErrInvalidMFACodePrefix)
	}

	s.auditMFAResetRequested(ctx, u.ID, u.Email)

	resetUrl := req.MfaResetUrl
	if resetUrl == "" {
		resetUrl = s.mfaResetUrl
	}

	// Per-source-IP budget on top of the per-address cooldown below, same as
	// RequestPasswordReset -- the cooldown alone doesn't stop an attacker
	// cycling through many distinct target addresses.
	origIp, _ := security.GetOrigIp(ctx)
	callerIP := model.FirstIP(origIp)
	if !s.isLocked(ctx, db.ScopeEmailSendByIP, callerIP) {
		s.recordEmailSendAttempt(ctx, callerIP)
		if s.tryConsumeEmailCooldown(ctx, db.ScopeEmailMFAReset, identifier) {
			go s.sendMfaResetEmail(u.ID, u.Email, resetUrl)
		}
	}

	return &authv1.RequestMfaResetResponse{}, nil
}

// sendMfaResetEmail generates a fresh (not-yet-active) TOTP secret, stores
// it alongside a reset token, and emails the reset link. Runs
// asynchronously; errors are logged only.
func (s *AuthServer) sendMfaResetEmail(userID, userEmail, resetUrl string) {
	lg := s.Logger().Derive(log.WithFunction("sendMfaResetEmail"))

	ctx := context.Background()

	secret, err := totp.GenerateSecret(20)
	if err != nil {
		lg.Errorf("failed to generate pending MFA secret: %v", err)
		return
	}

	token, err := s.DB().CreateMFAResetToken(ctx, userID, secret)
	if err != nil {
		lg.Errorf("failed to create MFA reset token: %v", err)
		return
	}

	svcToken, err := svctoken.MailSendToken(ctx, s.DB())
	if err != nil {
		lg.Errorf("failed to mint mail service token: %v", err)
		return
	}

	if _, err = s.mailClient.SendTemplate(
		svcToken,
		s.mfaResetEmailTemplate(s.mailerAddress, userEmail, userID, token.Token, resetUrl),
	); err != nil {
		lg.Errorf("failed to send MFA reset email: %v", err)
		return
	}
}

// mfaResetEmailTemplate builds the email template data for MFA reset
// emails, mirroring resetPasswordEmailTemplate. The reset URL carries the
// same u/t query params as the password-reset and verification emails.
func (s *AuthServer) mfaResetEmailTemplate(
	fromEmail, toEmail, userId, resetToken, resetUrl string,
) *mailclient.TemplateMail {
	return mailclient.NewTemplateMail(
		fromEmail, []string{toEmail}, nil, nil,
		"SwayRider - Reset Authenticator",
		"reset_mfa.html", "reset_mfa.txt",
		map[string]string{
			"Email": toEmail,
			"MfaResetURL": func() string {
				sep := "?"
				if strings.Contains(resetUrl, "?") {
					sep = "&"
				}
				return fmt.Sprintf("%s%su=%s&t=%s",
					resetUrl, sep,
					url.QueryEscape(userId),
					url.QueryEscape(resetToken))
			}(),
			"Year": fmt.Sprintf("%d", time.Now().Year()),
		},
	)
}
