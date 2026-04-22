// change_account.go implements admin endpoints for modifying user account levels.

package server

import (
	"context"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	authv1 "github.com/swayrider/protos/auth/v1"
	log "github.com/swayrider/swlib/logger"
)

// ChangeAccountType updates a user's account level (e.g., "free", "premium").
//
// This endpoint is restricted to admin users only. Account types are free-form
// strings that can be used to implement subscription tiers or feature flags.
//
// Returns:
//   - codes.NotFound: User not found
//   - codes.InvalidArgument: Empty account type
//   - codes.Internal: Database update failure
func (s *AuthServer) ChangeAccountType(
	ctx context.Context,
	req *authv1.ChangeAccountTypeRequest,
) (*authv1.ChangeAccountTypeResponse, error) {
	lg := s.Logger().Derive(log.WithFunction("ChangeAccountType"))

	// Check if the user exists !
	user, err := s.DB().GetUserByID(ctx, req.UserId)
	if err != nil {
		lg.Errorf("user %s not found: %v", req.UserId, err)
		return nil, status.Errorf(codes.NotFound, "user not found")
	}

	if req.AccountType == "" {
		lg.Errorf("account type is empty")
		return nil, status.Errorf(codes.InvalidArgument, "account type is empty")
	}

	// If the account types are equal, nothing to do
	if user.AccountLevel == req.AccountType {
		return &authv1.ChangeAccountTypeResponse{
			Message: fmt.Sprintf(
				"user account type already: %s", req.AccountType),
		}, nil
	}

	err = s.DB().ChangeAccountLevel(ctx, user.ID, req.AccountType)
	if err != nil {
		lg.Errorf("failed to update user account type: %v", err)
		return nil, status.Errorf(
			codes.Internal, "failed to update user account type: %v", err)
	}

	return &authv1.ChangeAccountTypeResponse{
		Message: fmt.Sprintf(
			"User account type updated to: %s", req.AccountType),
	}, nil
}
