// password_reset.go implements the password reset flow endpoints.
//
// The password reset flow:
//  1. User requests reset via RequestPasswordReset (sends email asynchronously)
//  2. User receives email with reset link containing user ID and token
//  3. User submits new password via ResetPassword with the token

package server

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	passwordvalidator "github.com/wagslane/go-password-validator"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"github.com/swayrider/grpcclients/mailclient"
	authv1 "github.com/swayrider/protos/auth/v1"
	"github.com/swayrider/authservice/internal/model"
	"github.com/swayrider/swlib/crypto"
	log "github.com/swayrider/swlib/logger"
)

// RequestPasswordReset initiates the password reset flow by sending a reset email.
//
// This endpoint always returns success to prevent email enumeration attacks.
// The reset email is sent asynchronously to avoid timing-based information leakage.
func (s *AuthServer) RequestPasswordReset(
	ctx context.Context,
	req *authv1.RequestPasswordResetRequest,
) (*authv1.RequestPasswordResetResponse, error) {
	// Send asynchronously to prevent timing attacks
	go s.sendPasswordResetEmail("", req.Email, req.ResetUrl)
	return &authv1.RequestPasswordResetResponse{}, nil
}

// ResetPassword completes the password reset flow by setting a new password.
//
// Validation steps:
//  1. Verify user exists
//  2. Retrieve and validate reset token (existence, expiration, match)
//  3. Validate new password meets entropy requirements
//  4. Hash and store new password
//  5. Delete the used reset token
//
// Returns:
//   - codes.InvalidArgument: User not found, token invalid/expired, or weak password
//   - codes.Internal: Database or hashing errors
func (s *AuthServer) ResetPassword(
	ctx context.Context,
	req *authv1.ResetPasswordRequest,
) (*authv1.ResetPasswordResponse, error) {
	lg := s.Logger().Derive(log.WithFunction("ResetPassword"))

	// Step 1: Verify user exists
	user, err := s.DB().GetUserByID(ctx, req.UserId)
	if err != nil {
		lg.Errorf("user not found: %s: %v", req.UserId, err)
		return nil, status.Errorf(codes.InvalidArgument, "user not found")
	}
	if user == nil {
		lg.Debugf("user not found: %s", req.UserId)
		return nil, status.Error(codes.InvalidArgument, "user not found")
	}

	// Step 2: Validate reset token
	token, err := s.DB().GetResetPasswordToken(ctx, &user.User)
	if err != nil {
		lg.Errorf(
			"failed to retrieve password reset token for user: %s: %v",
			req.UserId, err)
		return nil, status.Errorf(
			codes.InvalidArgument, "invalid token")
	}
	if !token.IsNotExpired() {
		lg.Warnf("reset password token for user %s is expired", user.ID)
		return nil, status.Errorf(codes.InvalidArgument, "token is expired")
	}
	if !token.Verify(req.UserId, req.Token) {
		lg.Warnf("reset password token for user %s does not match", user.ID)
		return nil, status.Errorf(codes.InvalidArgument, "invalid token")
	}

	// Step 3: Validate new password
	if req.NewPassword == "" {
		return nil, status.Errorf(
			codes.InvalidArgument,
			"new password cannot be empty")
	}

	err = passwordvalidator.Validate(req.NewPassword, crypto.PasswordMinEntropy)
	if err != nil {
		lg.Debugf("user password is too weak: %v", err)
		return nil, status.Errorf(
			codes.InvalidArgument,
			"password is too weak: %v", err)
	}

	// Step 4: Hash and store new password
	hashedPassword, err := crypto.CalculatePasswordHash(req.NewPassword)
	if err != nil {
		lg.Debugf("user password hashing error: %v", err)
		return nil, status.Errorf(codes.Internal, "failed to reset password")
	}

	err = s.DB().UpdatePassword(ctx, user.ID, hashedPassword)
	if err != nil {
		lg.Debugf("failed to reset password for user: %s: %v", user.Email, err)
		return nil, status.Errorf(codes.Internal, "failed to reset password")
	}

	// Step 5: Clean up used token
	err = s.DB().DeleteResetPasswordToken(ctx, user.ID)
	if err != nil {
		lg.Debugf("failed to delete password reset token: %v", err)
	}

	return &authv1.ResetPasswordResponse{
		Message: "Password reset successful",
	}, nil
}

// sendPasswordResetEmail creates a reset token and sends the password reset email.
//
// This is an internal helper that runs asynchronously. It can look up the user
// by either user ID or email address. Errors are logged but not returned since
// this runs in a goroutine.
func (s *AuthServer) sendPasswordResetEmail(
	userid string,
	userEmail string,
	resetUrl string,
) {
	lg := s.Logger().Derive(log.WithFunction("sendPasswordResetEmail"))

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

	// Create a new reset token (replaces any existing one)
	token, err := s.DB().CreateResetPasswordToken(ctx, &user.User)
	if err != nil {
		lg.Errorf("failed to create reset password token: %v", err)
		return
	}

	// Send the reset email via mailservice
	_, err = s.mailClient.SendTemplateInternal(
		s.resetPasswordEmailTemplate(
			s.mailerAddress,
			user.Email,
			user.ID,
			token.Token,
			resetUrl))
	if err != nil {
		lg.Errorf("failed to send password reset email: %v", err)
		return
	}
}

// resetPasswordEmailTemplate builds the email template data for password reset emails.
//
// The reset URL is constructed by appending query parameters to the provided base URL:
//   - u: URL-encoded user ID
//   - t: URL-encoded reset token
//
// Template variables passed to reset_password.html/txt:
//   - Email: The user's email address
//   - PasswordResetURL: The complete reset link
//   - Year: Current year for copyright notice
func (s *AuthServer) resetPasswordEmailTemplate(
	fromEmail string,
	toEmail string,
	userId string,
	resetToken string,
	resetUrl string,
) *mailclient.TemplateMail {
	return mailclient.NewTemplateMail(
		fromEmail, []string{toEmail}, nil, nil,
		"SwayRider - Reset Password",
		"reset_password.html", "reset_password.txt",
		map[string]string{
			"Email": toEmail,
			"PasswordResetURL": func() string {
				// Handle URLs that already have query parameters
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
