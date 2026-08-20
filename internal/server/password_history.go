// password_history.go implements the password-reuse gate: a new password is
// rejected when it matches a recent password hash recorded for the user
// (password_history table). It mirrors the breach-check helper's shape:
// a fixed message prefix the gateway matches on, and fail-open on any error.

package server

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ErrPasswordReusedPrefix is the fixed message prefix the API gateway matches
// on to surface a distinct "password reused" reason to clients. Keep it
// stable: the prefix is the contract, the tail may carry detail.
const ErrPasswordReusedPrefix = "password has been used before"

// checkNotReused rejects newPassword when it matches a recent history hash of
// the user. On any database error it logs and fails open (returns nil) so a
// history outage never blocks a legitimate password change.
func (s *AuthServer) checkNotReused(ctx context.Context, userID, newPassword string) error {
	reused, err := s.DB().CheckPasswordReuse(ctx, userID, newPassword)
	if err != nil {
		s.l.Debugf("password reuse check failed, allowing password (fail open): %v", err)
		return nil
	}
	if reused {
		return status.Errorf(codes.InvalidArgument,
			"%s: choose a password you have not used recently", ErrPasswordReusedPrefix)
	}
	return nil
}
