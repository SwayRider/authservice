// registration.go implements user registration and email verification endpoints.
//
// This file handles:
//   - New user registration with password validation
//   - Email verification token creation and validation
//   - Sending verification emails via mailservice

package server

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	passwordvalidator "github.com/wagslane/go-password-validator"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"github.com/swayrider/grpcclients/mailclient"
	authv1 "github.com/swayrider/protos/auth/v1"
	"github.com/swayrider/authservice/internal/db"
	"github.com/swayrider/authservice/internal/model"
	"github.com/swayrider/authservice/internal/svctoken"
	"github.com/swayrider/swlib/crypto"
	log "github.com/swayrider/swlib/logger"
	"github.com/swayrider/swlib/security"
)

// Register creates a new user account with the provided email and password.
//
// The registration flow:
//  1. Validate password meets minimum entropy requirements
//  2. Hash password using Argon2id
//  3. In INVITE_ONLY mode: verify email is in the invite list
//  4. Create user record in database
//  5. In INVITE_ONLY mode: consume (delete) the invite
//  6. Asynchronously send verification email
//
// The verification URL in the request is provided by the caller (mobile app, web app)
// since different clients have different verification page URLs.
//
// To prevent account enumeration, an outcome that could reveal whether an
// email is already registered returns the same generic success response
// with an empty UserId -- mirroring the anti-enumeration pattern already
// used by VerifyEmail and RequestPasswordReset in this file. If the email
// turns out to already have an account, the real owner is notified
// asynchronously via the same password-reset email RequestPasswordReset
// would send them.
//
// Deliberate, scoped exception: in INVITE_ONLY mode, a non-invited email
// gets an explicit codes.PermissionDenied rather than the generic response.
// This intentionally reveals invite status to an unauthenticated caller --
// an owner-approved tradeoff (see CLAUDE.md and Docs/AuthImprovement) made
// because the invite pool is small, invited users register quickly, and
// completing registration for an invited email requires mailbox access
// regardless of whether invite status is known.
//
// Returns:
//   - codes.InvalidArgument: If password is too weak
//   - codes.PermissionDenied: In INVITE_ONLY mode, if the email has no invitation
//   - codes.Internal: On infrastructure/database errors
func (s *AuthServer) Register(
	ctx context.Context,
	req *authv1.RegisterRequest,
) (*authv1.RegisterResponse, error) {
	lg := s.Logger().Derive(log.WithFunction("Register"))

	err := passwordvalidator.Validate(req.Password, crypto.PasswordMinEntropy)
	if err != nil {
		lg.Debugf("user password is too weak: %v", err)
		return nil, status.Errorf(
			codes.InvalidArgument, "password is too weak: %v", err)
	}

	if err := s.checkNotBreached(ctx, req.Password); err != nil {
		lg.Debugf("registration rejected: %v", err)
		// No user exists yet at this point; the attempted email is all we
		// can attribute the rejection to.
		s.auditBreachedPasswordRejected(ctx, nil, req.Email)
		return nil, err
	}

	hashedPassword, err := crypto.CalculatePasswordHash(req.Password)
	if err != nil {
		lg.Debugf("user password hashing error: %v", err)
		return nil, status.Errorf(
			codes.Internal, "password error")
	}

	resp := &authv1.RegisterResponse{
		Message: "If this email is eligible for registration, check your inbox to continue.",
	}

	// Per-source-IP budget on top of the per-address cooldown below: the
	// cooldown alone doesn't stop an attacker cycling through many distinct
	// target addresses. Only gates the mail send -- account creation and
	// invite handling proceed regardless, same as the per-address cooldown.
	origIp, _ := security.GetOrigIp(ctx)
	callerIP := model.FirstIP(origIp)
	ipAllowsEmailSend := !s.isLocked(ctx, db.ScopeEmailSendByIP, callerIP)

	if s.registrationMode == registrationModeInviteOnly {
		invited, err := s.DB().IsEmailInvited(ctx, req.Email)
		if err != nil {
			lg.Errorf("failed to check invite for %s: %v", req.Email, err)
			return nil, status.Errorf(codes.Internal, "registration error")
		}
		if !invited {
			lg.Debugf("registration attempt for non-invited email %s", req.Email)
			return nil, status.Errorf(codes.PermissionDenied, "invitation required")
		}
	}

	verificationUrl := req.VerificationUrl
	if verificationUrl == "" {
		verificationUrl = s.verificationUrl
	}

	userid, err := s.DB().RegisterUser(ctx, req.Email, hashedPassword)
	if err != nil {
		if errors.Is(err, db.ErrUniqueViolation) {
			lg.Debugf("registration attempt for existing email %s", req.Email)
			// Notify the real account owner the same way RequestPasswordReset
			// would -- shares its cooldown scope/budget since it's
			// functionally the same action (a password-reset email to this
			// address).
			if ipAllowsEmailSend {
				s.recordEmailSendAttempt(ctx, callerIP)
				if s.tryConsumeEmailCooldown(ctx, db.ScopeEmailPasswordReset, normalizeIdentifier(req.Email)) {
					go s.sendPasswordResetEmail("", req.Email, s.resetPasswordUrl)
				}
			}
			return resp, nil
		}
		lg.Errorf("registration error for user with email %s: %v", req.Email, err)
		return nil, status.Errorf(codes.Internal, "registration error")
	}
	lg.Debugf("user registered with ID: %s", userid)
	s.auditRegister(ctx, userid, req.Email)

	// Seed the password history with the initial password so a later change
	// cannot rotate back to it. Failures are log-only: history is a
	// hardening feature, not a core-path dependency.
	if err := s.DB().AddToPasswordHistory(ctx, userid, hashedPassword); err != nil {
		lg.Warnf("failed to seed password history for %s: %v", userid, err)
	}

	if s.registrationMode == registrationModeInviteOnly {
		if err := s.DB().ConsumeInvite(ctx, req.Email); err != nil {
			lg.Errorf("failed to consume invite for %s: %v", req.Email, err)
		}
	}

	if ipAllowsEmailSend {
		s.recordEmailSendAttempt(ctx, callerIP)
		if s.tryConsumeEmailCooldown(ctx, db.ScopeEmailVerification, normalizeIdentifier(req.Email)) {
			go s.sendVerificationEmail(userid, "", verificationUrl)
		}
	}

	return resp, nil
}

// VerifyEmail sends a new verification email to the specified address.
//
// This endpoint is public and always returns success to prevent email enumeration.
// The verification email is sent asynchronously.
func (s *AuthServer) VerifyEmail(
	ctx context.Context,
	req *authv1.VerifyEmailRequest,
) (*authv1.VerifyEmailResponse, error) {
	// Send asynchronously to prevent timing attacks
	verificationUrl := req.VerificationUrl
	if verificationUrl == "" {
		verificationUrl = s.verificationUrl
	}

	// Per-source-IP budget (shared with Register/RequestPasswordReset via
	// db.ScopeEmailSendByIP) on top of the per-address cooldown below: the
	// cooldown alone doesn't stop an attacker cycling through many distinct
	// target addresses.
	origIp, _ := security.GetOrigIp(ctx)
	callerIP := model.FirstIP(origIp)
	if !s.isLocked(ctx, db.ScopeEmailSendByIP, callerIP) {
		s.recordEmailSendAttempt(ctx, callerIP)
		// Cooldown check runs synchronously and shares its budget with
		// Register (same db.ScopeEmailVerification) so an attacker can't
		// reset it by alternating endpoints for the same address. The
		// response stays unconditionally generic either way -- only the send
		// is skipped.
		if s.tryConsumeEmailCooldown(ctx, db.ScopeEmailVerification, normalizeIdentifier(req.Email)) {
			go s.sendVerificationEmail("", req.Email, verificationUrl)
		}
	}

	return &authv1.VerifyEmailResponse{}, nil
}

// sendVerificationEmail creates a verification token and sends the verification email.
//
// This is an internal helper that runs asynchronously. It can look up the user
// by either user ID or email address. Errors are logged but not returned since
// this runs in a goroutine.
func (s *AuthServer) sendVerificationEmail(
	userid string,
	userEmail string,
	verificationUrl string,
) {
	lg := s.Logger().Derive(log.WithFunction("sendVerificationEmail"))

	var user *model.UserInternal
	var err error

	ctx := context.Background()
	if userid != "" {
		user, err = s.DB().GetUserByID(ctx, userid)
	} else {
		user, err = s.DB().GetUserByEmail(ctx, userEmail)
	}
	if err != nil {
		lg.Errorf("user %s not found: %v", userid, err)
		return
	}
	if user == nil {
		lg.Debugln("user not found")
		return
	}

	token, err := s.DB().CreateVerificationToken(ctx, &user.User)
	if err != nil {
		lg.Errorf("failed to create verification token: %v", err)
		return
	}

	svcToken, err := svctoken.MailSendToken(ctx, s.DB())
	if err != nil {
		lg.Errorf("failed to mint mail service token: %v", err)
		return
	}

	_, err = s.mailClient.SendTemplate(
		svcToken,
		s.confirmEmailTemplate(
			s.mailerAddress,
			user.Email,
			user.ID,
			token.Token,
			verificationUrl))
	if err != nil {
		lg.Errorf("failed to send verification email: %v", err)
		return
	}
}

// confirmEmailTemplate builds the email template data for verification emails.
//
// The verification URL is constructed by appending query parameters to the
// provided base URL:
//   - u: URL-encoded user ID
//   - t: URL-encoded verification token
//
// Template variables passed to verify_user.html/txt:
//   - Email: The user's email address
//   - VerificationURL: The complete verification link
//   - Year: Current year for copyright notice
func (s *AuthServer) confirmEmailTemplate(
	fromEmail string,
	toEmail string,
	userId string,
	verificationToken string,
	verificationUrl string,
) *mailclient.TemplateMail {
	return mailclient.NewTemplateMail(
		fromEmail, []string{toEmail}, nil, nil,
		"SwayRider - Confirm Email",
		"verify_user.html", "verify_user.txt",
		map[string]string{
			"Email": toEmail,
			"VerificationURL": func() string {
				// Handle URLs that already have query parameters
				sep := "?"
				if strings.Contains(verificationUrl, "?") {
					sep = "&"
				}
				return fmt.Sprintf("%s%su=%s&t=%s",
					verificationUrl, sep,
					url.QueryEscape(userId),
					url.QueryEscape(verificationToken))
			}(),
			"Year": fmt.Sprintf("%d", time.Now().Year()),
		})
}
