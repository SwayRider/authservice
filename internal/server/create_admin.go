// create_admin.go implements the admin user creation endpoint.
//
// This endpoint is restricted to existing admin users and allows creating
// new administrator accounts with full system privileges.

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

// CreateAdmin creates a new administrator user account.
//
// This endpoint is restricted to existing admin users only. The new admin
// will have full system privileges including access to all admin-only endpoints.
//
// The password must meet the minimum entropy requirements enforced by
// the go-password-validator library.
//
// Returns:
//   - codes.InvalidArgument: Password too weak
//   - codes.Internal: Database or hashing errors
func (s *AuthServer) CreateAdmin(
	ctx context.Context,
	req *authv1.CreateAdminRequest,
) (*authv1.CreateAdminResponse, error) {
	lg := s.Logger().Derive(log.WithFunction("CreateAdmin"))

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

	userid, err := s.DB().CreateAdminUser(ctx, req.Email, hashedPassword)
	if err != nil {
		lg.Errorf("failed to create admin user: %v", err)
		return nil, status.Errorf(
			codes.Internal, "failed to create admin user: %v", err)
	}
	lg.Debugf("admin user created: %s", userid)

	return &authv1.CreateAdminResponse{
		UserId:  userid,
		Message: "admin user created",
	}, nil
}
