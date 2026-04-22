// user.go implements user information lookup endpoints.
//
// This file provides:
//   - WhoAmI: Current user info (for authenticated users)
//   - WhoIs: Lookup any user (for admins and service clients)

package server

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	authv1 "github.com/swayrider/protos/auth/v1"
	"github.com/swayrider/authservice/internal/model"
	log "github.com/swayrider/swlib/logger"
)

// WhoAmI returns information about the currently authenticated user.
//
// This endpoint extracts the user ID from the JWT claims and returns
// the user's profile information including admin status, verification
// status, and account level.
func (s *AuthServer) WhoAmI(
	ctx context.Context,
	req *authv1.WhoAmIRequest,
) (*authv1.WhoAmIResponse, error) {
	lg := s.Logger().Derive(log.WithFunction("WhoAmI"))

	u, err := s.getUserFromClaims(ctx)
	if err != nil {
		lg.Errorf("no valid user: %v", err)
		return nil, err
	}

	return &authv1.WhoAmIResponse{
		UserId:      u.ID,
		Email:       u.Email,
		IsAdmin:     u.IsAdmin,
		IsVerified:  u.IsVerified,
		AccountType: u.AccountLevel,
	}, nil
}

// WhoIs returns information about any user by ID or email.
//
// This endpoint is restricted to:
//   - Admin users (full access)
//   - Service clients with the "user:read" scope
//
// The user can be looked up by either:
//   - UserId: The user's unique identifier
//   - Email: The user's email address
//
// Returns:
//   - codes.NotFound: User not found
//   - codes.InvalidArgument: Invalid lookup type
func (s *AuthServer) WhoIs(
	ctx context.Context,
	req *authv1.WhoIsRequest,
) (*authv1.WhoIsResponse, error) {
	lg := s.Logger().Derive(log.WithFunction("WhoIs"))

	var err error
	var user *model.UserInternal

	// Handle different lookup types via oneof
	switch v := req.WhoisOneof.(type) {
	case *authv1.WhoIsRequest_UserId:
		user, err = s.DB().GetUserByID(ctx, v.UserId)
		if err != nil {
			lg.Errorf("user %s not found: %v", v.UserId, err)
			return nil, status.Errorf(codes.NotFound, "user not found")
		}
	case *authv1.WhoIsRequest_Email:
		user, err = s.DB().GetUserByEmail(ctx, v.Email)
		if err != nil {
			lg.Errorf("user %s not found: %v", v.Email, err)
			return nil, status.Errorf(codes.NotFound, "user not found")
		}
	default:
		lg.Errorf("unknown whois type: %T", v)
		return nil, status.Errorf(codes.InvalidArgument, "unknown whois type")
	}

	return &authv1.WhoIsResponse{
		UserId:      user.ID,
		Email:       user.Email,
		IsAdmin:     user.IsAdmin,
		IsVerified:  user.IsVerified,
		AccountType: user.AccountLevel,
	}, nil
}
