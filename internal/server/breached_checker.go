package server

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// BreachedChecker reports whether a password has appeared in a known data
// breach. It mirrors the MailSender/Database interface pattern so handlers can
// be tested with a stub. Implemented by *hibp.Client.
type BreachedChecker interface {
	IsBreached(ctx context.Context, password string) (bool, int, error)
}

// ErrBreachedPasswordPrefix is the fixed message prefix the API gateway
// matches on to surface a distinct "breached password" reason to clients.
// Keep it stable: the prefix is the contract, the tail may carry detail.
const ErrBreachedPasswordPrefix = "password has appeared in a known data breach"

// checkNotBreached rejects password when it has appeared in a known data
// breach. On any HIBP API error it logs and fails open (returns nil) so an
// HIBP outage never blocks users. A nil checker (feature not configured)
// always allows.
func (s *AuthServer) checkNotBreached(ctx context.Context, password string) error {
	if s.breached == nil {
		return nil
	}
	breached, count, err := s.breached.IsBreached(ctx, password)
	if err != nil {
		s.l.Debugf("breach check failed, allowing password (fail open): %v", err)
		return nil
	}
	if breached {
		return status.Errorf(codes.InvalidArgument,
			"%s (found %d times)", ErrBreachedPasswordPrefix, count)
	}
	return nil
}
