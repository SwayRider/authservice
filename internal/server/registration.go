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
	"github.com/swayrider/swlib/crypto"
	log "github.com/swayrider/swlib/logger"
)

// Register creates a new user account with the provided email and password.
//
// The registration flow:
//  1. Validate password meets minimum entropy requirements
//  2. Hash password using Argon2id
//  3. Create user record in database
//  4. Asynchronously send verification email
//
// Returns:
//   - codes.InvalidArgument: If password is too weak
//   - codes.AlreadyExists: If email is already registered
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

	hashedPassword, err := crypto.CalculatePasswordHash(req.Password)
	if err != nil {
		lg.Debugf("user password hashing error: %v", err)
		return nil, status.Errorf(
			codes.Internal, "password error")
	}

	userid, err := s.DB().RegisterUser(ctx, req.Email, hashedPassword)
	if err != nil {
		lg.Debugf("user %s failed to self-register: %v", req.Email, err)
		if errors.Is(err, db.ErrUniqueViolation) {
			return nil, status.Errorf(
				codes.AlreadyExists,
				"user with email %s already exists", req.Email)
		}
		return nil, status.Errorf(
			codes.Internal,
			"registration error for user with email: %s", req.Email)
	}
	lg.Debugf("user resigered with ID: %s", userid)

	go s.sendVerificationEmail(userid, "", req.VerificationUrl)

	return &authv1.RegisterResponse{
		UserId:  userid,
		Message: "User registered successfully",
	}, nil
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
	go s.sendVerificationEmail("", req.Email, req.VerificationUrl)

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

	_, err = s.mailClient.SendTemplateInternal(
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
