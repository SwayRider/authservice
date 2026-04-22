// claims.go provides helper functions for extracting user information from JWT claims.
//
// These functions are used by protected endpoints to identify the authenticated user
// and validate their session.

package server

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"github.com/swayrider/authservice/internal/model"
	log "github.com/swayrider/swlib/logger"
	"github.com/swayrider/swlib/security"
)

// getUserFromClaims gets the user from the claims
//
// Parameters:
//   - ctx: The context of the request
//
// Returns:
//   - *model.UserInternal: The user from the claims
//   - error: An error if the request fails
func (s *AuthServer) getUserFromClaims(
	ctx context.Context,
) (*model.UserInternal, error) {
	lg := s.Logger().Derive(log.WithFunction("getUserFromClaims"))

	claims, ok := security.GetClaims(ctx)
	if !ok {
		lg.Debugln("Claims not found in grpc context")
		return nil, status.Errorf(codes.Unauthenticated, "claims not found")
	}

	id, err := claims.GetSubject()
	if err != nil {
		lg.Debugf("User ID not found in claims: %v", err)
		return nil, status.Errorf(codes.NotFound, "user not found")
	}
	if id == "" {
		lg.Debugln("User ID not found in claims")
		return nil, status.Errorf(codes.NotFound, "user not found")
	}

	u, err := s.DB().GetUserByID(ctx, id)
	if err != nil {
		lg.Debugf("User %s not found: %v", id, err)
		return nil, status.Errorf(codes.NotFound, "user not found")
	}

	return u, nil
}

// getJwtIDFromClaims extracts the JWT ID (jti) from the context claims.
// This is used to bind refresh tokens to specific access tokens.
func (s *AuthServer) getJwtIDFromClaims(
	ctx context.Context,
) (string, error) {
	lg := s.Logger().Derive(log.WithFunction("getJwtIDFromClaims"))

	claims, ok := security.GetClaims(ctx)
	if !ok {
		lg.Debugln("Claims not found in grpc context")
		return "", status.Errorf(codes.Unauthenticated, "claims not found")
	}

	id := claims.ID
	if id == "" {
		lg.Debugln("JWT ID not found in claims")
		return "", status.Errorf(codes.NotFound, "jwt not found")
	}
	return id, nil
}
