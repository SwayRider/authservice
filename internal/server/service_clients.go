// service_clients.go implements service client management endpoints.
//
// Service clients are used for service-to-service authentication following
// the OAuth2 client credentials flow. Each service client has:
//   - A unique client ID (generated from the name)
//   - A client secret (64-byte random string, hashed before storage)
//   - A list of scopes defining permitted operations
//
// These endpoints are restricted to admin users only.

package server

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	authv1 "github.com/swayrider/protos/auth/v1"
	"github.com/swayrider/authservice/internal/db"
	"github.com/swayrider/swlib/crypto"
	log "github.com/swayrider/swlib/logger"
)

// CreateServiceClient creates a new service client for service-to-service authentication.
//
// The client secret is generated as a 64-byte secure random string and returned
// in the response. This is the ONLY time the plaintext secret is available -
// it is hashed using Argon2id before storage and cannot be retrieved later.
//
// Required fields:
//   - Name: Unique identifier for the service client
//   - Scopes: At least one scope must be provided
//
// Returns:
//   - codes.InvalidArgument: No scopes provided
//   - codes.AlreadyExists: Client with same name already exists
//   - codes.Internal: Secret generation, hashing, or database errors
func (s *AuthServer) CreateServiceClient(
	ctx context.Context,
	req *authv1.CreateServiceClientRequest,
) (*authv1.CreateServiceClientResponse, error) {
	lg := s.Logger().Derive(log.WithFunction("CreateServiceClient"))

	if len(req.Scopes) == 0 {
		return nil, status.Error(
			codes.InvalidArgument, "no scopes provided")
	}

	clientSecret, err := crypto.GenerateSecureRandomString(64)
	if err != nil {
		lg.Errorf("failed to generate client secret: %v", err)
		return nil, status.Error(
			codes.Internal, "failed to generate client secret")
	}
	secretHash, err := crypto.CalculatePasswordHash(clientSecret)
	if err != nil {
		lg.Errorf("failed to hash client secret: %v", err)
		return nil, status.Error(
			codes.Internal, "failed to hash client secret")
	}

	clientId, err := s.DB().CreateServiceClient(
		ctx, req.Name, req.Description, req.Scopes, secretHash,
	)
	if err != nil {
		lg.Debugf("failed to create service client %s: %v", req.Name, err)
		if errors.Is(err, db.ErrUniqueViolation) {
			return nil, status.Errorf(
				codes.AlreadyExists, "client id with name %s already exists", req.Name)
		}
		return nil, status.Errorf(
			codes.Internal, "failed to create service client: %s", req.Name)
	}

	return &authv1.CreateServiceClientResponse{
		ClientId:     clientId,
		ClientSecret: clientSecret,
	}, nil
}

// DeleteServiceClient removes a service client from the system.
//
// Once deleted, the client can no longer authenticate. Any existing tokens
// issued to this client will continue to work until they expire, but no
// new tokens can be obtained.
//
// Returns:
//   - codes.Internal: Database error during deletion
func (s *AuthServer) DeleteServiceClient(
	ctx context.Context,
	req *authv1.DeleteServiceClientRequest,
) (*authv1.DeleteServiceClientResponse, error) {
	lg := s.Logger().Derive(log.WithFunction("DeleteServiceClient"))

	err := s.DB().DeleteServiceClient(ctx, req.ClientId)
	if err != nil {
		lg.Debugf("failed to delete service client %s: %v", req.ClientId, err)
		return nil, status.Errorf(
			codes.Internal, "failed to delete service client: %s", req.ClientId)
	}

	return &authv1.DeleteServiceClientResponse{
		Message: "Service client deleted",
	}, nil
}

// ListServiceClients returns a paginated list of all service clients.
//
// The response includes the client ID, name, description, and scopes for each
// client. The client secret is never included as it is stored only as a hash.
//
// Pagination:
//   - Page: 1-indexed page number (defaults to 1 if < 0)
//   - PageSize: Number of clients per page (defaults to 10 if < 0)
//
// Returns:
//   - codes.Internal: Database error during listing
func (s *AuthServer) ListServiceClients(
	ctx context.Context,
	req *authv1.ListServiceClientsRequest,
) (*authv1.ListServiceClientsResponse, error) {
	lg := s.Logger().Derive(log.WithFunction("ListServiceClients"))

	page := int(req.Page)
	pageSize := int(req.PageSize)

	if page < 0 {
		page = 1
	}
	if pageSize < 0 {
		pageSize = 10
	}

	numClients, err := s.DB().CountServiceClients(ctx)
	if err != nil {
		lg.Debugf("failed to count service clients: %v", err)
		return nil, status.Errorf(
			codes.Internal, "failed to count service clients")
	}

	clients, err := s.DB().ListServiceClients(ctx, page, pageSize)
	if err != nil {
		lg.Debugf("failed to list service clients: %v", err)
		return nil, status.Errorf(
			codes.Internal, "failed to list service clients")
	}

	return &authv1.ListServiceClientsResponse{
		Clients: func() []*authv1.ListServiceClientsResponse_Client {
			res := make([]*authv1.ListServiceClientsResponse_Client, 0, len(clients))
			for _, c := range clients {
				res = append(res, &authv1.ListServiceClientsResponse_Client{
					ClientId:    c.ClientID,
					Name:        c.Name,
					Description: c.Description,
					Scopes:      c.Scopes,
				})
			}
			return res
		}(),
		NumClients: int32(numClients),
	}, nil

}
