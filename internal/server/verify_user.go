// verify_user.go implements email verification token endpoints.
//
// This file handles:
//   - Creating verification tokens for logged-in unverified users
//   - Validating verification tokens and marking users as verified

package server

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
	authv1 "github.com/swayrider/protos/auth/v1"
	log "github.com/swayrider/swlib/logger"
)

// CreateVerificationToken creates a new verification token for the current user.
//
// This endpoint is only available to logged-in users who are NOT yet verified.
// The token can be used to verify the user's email address.
//
// Returns the token value and expiration time. The caller is responsible for
// sending the token to the user (e.g., via a verification URL in an email).
func (s *AuthServer) CreateVerificationToken(
	ctx context.Context,
	req *authv1.CreateVerificationTokenRequest,
) (*authv1.CreateVerificationTokenResponse, error) {
	lg := s.Logger().Derive(log.WithFunction("CreateVerificationToken"))

	u, err := s.getUserFromClaims(ctx)
	if err != nil {
		lg.Errorf("no valid user: %v", err)
		return nil, err
	}

	token, err := s.DB().CreateVerificationToken(ctx, &u.User)
	if err != nil {
		lg.Errorf("failed to create verification token: %v", err)
		return nil, err
	}
	lg.Debugf("verification token created for user %s", u.ID)

	return &authv1.CreateVerificationTokenResponse{
		UserId:     u.ID,
		Token:      token.Token,
		ValidUntil: timestamppb.New(token.ValidUntil),
	}, nil
}

// CheckVerificationToken validates a verification token and marks the user as verified.
//
// Validation steps:
//  1. Verify user exists
//  2. Check user is not already verified
//  3. Retrieve and validate token (existence, expiration, match)
//  4. Mark user as verified
//  5. Delete the used verification token
//
// Returns:
//   - codes.NotFound: User not found
//   - codes.AlreadyExists: User already verified
//   - codes.Unauthenticated: Token invalid or expired
func (s *AuthServer) CheckVerificationToken(
	ctx context.Context,
	req *authv1.CheckVerificationTokenRequest,
) (*authv1.CheckVerificationTokenResponse, error) {
	lg := s.Logger().Derive(log.WithFunction("CheckVerificationToken"))

	u, err := s.DB().GetUserByID(ctx, req.UserId)
	if err != nil {
		lg.Errorf("user %s not found: %v", req.UserId, err)
		return nil, status.Errorf(codes.NotFound, "user not found")
	}
	if u.IsVerified {
		lg.Debugf("user %s already verified", req.UserId)
		return nil, status.Errorf(codes.AlreadyExists, "user already verified")
	}

	token, err := s.DB().GetVerificationToken(ctx, &u.User)
	if err != nil {
		lg.Errorf("failed to retrieve verification token: %v", err)
		return nil, status.Errorf(codes.Unauthenticated, "invalid token")
	}
	if !token.IsNotExpired() {
		lg.Warnf("verification token for user %s expired", req.UserId)
		return nil, status.Errorf(codes.Unauthenticated, "token expired")
	}
	if !token.Verify(req.UserId, req.Token) {
		lg.Warnf("invalid verification token for user %s", req.UserId)
		return nil, status.Errorf(codes.Unauthenticated, "invalid token")
	}

	err = s.DB().MarkUserVerified(ctx, u.ID)
	if err != nil {
		lg.Errorf("failed to mark user as verified: %v", err)
		return nil, status.Errorf(
			codes.Internal, "verification error")
	}
	if err = s.DB().DeleteVerificationToken(ctx, u.ID); err != nil {
		lg.Warnf("failed to delete verification token: %v", err)
	}

	lg.Debugf("User %s verified", req.UserId)

	return &authv1.CheckVerificationTokenResponse{IsValid: true}, nil
}
