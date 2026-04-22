// change_password.go implements the password change endpoint for authenticated users.
//
// This allows users to update their password by providing their current password
// and a new password that meets the entropy requirements.

package server

import (
	"context"

	passwordvalidator "github.com/wagslane/go-password-validator"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	authv1 "github.com/swayrider/protos/auth/v1"
	"github.com/swayrider/swlib/crypto"
	log "github.com/swayrider/swlib/logger"
)

// ChangePassword updates the password for the currently authenticated user.
//
// Validation steps:
//  1. Verify new password differs from old password
//  2. Validate new password meets entropy requirements
//  3. Verify old password matches stored hash
//  4. Hash and store new password
//
// Returns:
//   - codes.InvalidArgument: New password same as old, empty, or too weak
//   - codes.Unauthenticated: Old password incorrect
//   - codes.Internal: Database or hashing errors
func (s *AuthServer) ChangePassword(
	ctx context.Context,
	req *authv1.ChangePasswordRequest,
) (*authv1.ChangePasswordResponse, error) {
	lg := s.Logger().Derive(log.WithFunction("ChangePassword"))

	if req.OldPassword == req.NewPassword {
		return nil, status.Errorf(
			codes.InvalidArgument,
			"new password must be different from old password")
	}

	if req.NewPassword == "" {
		return nil, status.Errorf(
			codes.InvalidArgument,
			"new password cannot be empty")
	}

	err := passwordvalidator.Validate(req.NewPassword, crypto.PasswordMinEntropy)
	if err != nil {
		lg.Debugf("user password is too weak: %v", err)
		return nil, status.Errorf(
			codes.InvalidArgument,
			"password is too weak: %v", err)
	}

	user, err := s.getUserFromClaims(ctx)
	if err != nil {
		lg.Errorf("no valid user: %v", err)
		return nil, err
	}

	if !user.PasswordHash.Valid {
		lg.Debugf("user %s has an invalid password", user.Email)
		return nil, status.Error(
			codes.Internal,
			"invalid password state")
	}

	var passwordOk bool
	passwordOk, err = crypto.VerifyPassword(
		user.PasswordHash.String, req.OldPassword)
	if err != nil {
		lg.Debugf("user password verification error: %v", err)
		return nil, status.Errorf(codes.Unauthenticated, "invalid old password")
	}
	if !passwordOk {
		lg.Debugf(
			"user %s failed to change password: invalid old password",
			user.Email)
		return nil, status.Error(codes.Unauthenticated, "invalid old password")
	}

	hashedPassword, err := crypto.CalculatePasswordHash(req.NewPassword)
	if err != nil {
		lg.Debugf("user password hashing error: %v", err)
		return nil, status.Errorf(codes.Internal, "failed to change password")
	}

	err = s.DB().UpdatePassword(ctx, user.ID, hashedPassword)
	if err != nil {
		lg.Debugf("user %s failed to change password: %v", user.Email, err)
		return nil, status.Errorf(codes.Internal, "failed to change password")
	}

	return &authv1.ChangePasswordResponse{
		Message: "Password changed successfully",
	}, nil
}
