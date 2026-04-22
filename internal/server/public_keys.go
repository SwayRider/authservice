// public_keys.go implements the JWT public key distribution endpoint.
//
// Other services use this endpoint to obtain the public keys needed to
// verify JWTs issued by the authservice. Multiple keys may be returned
// during key rotation periods.

package server

import (
	"context"
	"encoding/base64"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	authv1 "github.com/swayrider/protos/auth/v1"
	log "github.com/swayrider/swlib/logger"
)

// PublicKeys returns the current JWT verification public keys as base64-encoded PEM.
// Multiple keys may be returned during key rotation to support seamless transitions.
func (s *AuthServer) PublicKeys(
	ctx context.Context,
	req *authv1.PublicKeysRequest,
) (*authv1.PublicKeysResponse, error) {
	lg := s.Logger().Derive(log.WithFunction("PublicKeys"))

	keys, err := s.DB().GetVerificationKeys(ctx)
	if err != nil {
		lg.Errorf("failed to retrieve keys: %v", err)
		return nil, status.Errorf(codes.Internal, "failed to retrieve keys")
	}

	base64Keys := make([]string, 0, len(keys))
	for _, key := range keys {
		base64Keys = append(base64Keys, base64.StdEncoding.EncodeToString([]byte(key)))
	}

	return &authv1.PublicKeysResponse{
		//Keys: keys,
		Keys: base64Keys,
	}, nil
}

