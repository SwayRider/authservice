package server

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	authv1 "github.com/swayrider/protos/auth/v1"
	"github.com/swayrider/authservice/internal/model"
)

// =============================================================================
// CreateServiceClient Tests
// =============================================================================

func TestCreateServiceClient_NoScopes(t *testing.T) {
	// CreateServiceClient must reject requests with no scopes before touching the DB.
	srv := newTestServer(&mockDB{}, &noopMailSender{})
	ctx := context.Background()

	_, err := srv.CreateServiceClient(ctx, &authv1.CreateServiceClientRequest{
		Name:   "my-client",
		Scopes: []string{},
	})
	if err == nil {
		t.Fatal("expected error for empty scopes, got nil")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("code = %v, want %v", st.Code(), codes.InvalidArgument)
	}
}

func TestCreateServiceClient_NilScopes(t *testing.T) {
	srv := newTestServer(&mockDB{}, &noopMailSender{})
	ctx := context.Background()

	_, err := srv.CreateServiceClient(ctx, &authv1.CreateServiceClientRequest{
		Name:   "my-client",
		Scopes: nil,
	})
	if err == nil {
		t.Fatal("expected error for nil scopes, got nil")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("code = %v, want %v", st.Code(), codes.InvalidArgument)
	}
}

// =============================================================================
// ListServiceClients Tests
// =============================================================================

func TestListServiceClients_PaginationDefaults(t *testing.T) {
	var calledPage, calledPageSize int

	mdb := &mockDB{
		listServiceClientsFn: func(_ context.Context, page, pageSize int) ([]model.ServiceClient, error) {
			calledPage = page
			calledPageSize = pageSize
			return nil, nil
		},
	}
	srv := newTestServer(mdb, &noopMailSender{})
	ctx := context.Background()

	// page < 0 should be clamped to 1; pageSize < 0 should be clamped to 10
	_, err := srv.ListServiceClients(ctx, &authv1.ListServiceClientsRequest{
		Page:     -1,
		PageSize: -1,
	})
	if err != nil {
		t.Fatalf("ListServiceClients failed: %v", err)
	}
	if calledPage != 1 {
		t.Errorf("ListServiceClients called with page=%d, want 1", calledPage)
	}
	if calledPageSize != 10 {
		t.Errorf("ListServiceClients called with pageSize=%d, want 10", calledPageSize)
	}
}

func TestListServiceClients_Returns(t *testing.T) {
	clients := []model.ServiceClient{
		{ClientID: "c1", Name: "client-one", Scopes: []string{"read"}},
		{ClientID: "c2", Name: "client-two", Scopes: []string{"write"}},
	}
	mdb := &mockDB{
		countServiceClientsFn: func(_ context.Context) (int, error) {
			return len(clients), nil
		},
		listServiceClientsFn: func(_ context.Context, _, _ int) ([]model.ServiceClient, error) {
			return clients, nil
		},
	}
	srv := newTestServer(mdb, &noopMailSender{})
	ctx := context.Background()

	resp, err := srv.ListServiceClients(ctx, &authv1.ListServiceClientsRequest{
		Page:     1,
		PageSize: 10,
	})
	if err != nil {
		t.Fatalf("ListServiceClients failed: %v", err)
	}
	if int(resp.NumClients) != len(clients) {
		t.Errorf("NumClients = %d, want %d", resp.NumClients, len(clients))
	}
	if len(resp.Clients) != len(clients) {
		t.Errorf("len(Clients) = %d, want %d", len(resp.Clients), len(clients))
	}
	if resp.Clients[0].ClientId != "c1" {
		t.Errorf("first client ID = %q, want %q", resp.Clients[0].ClientId, "c1")
	}
}
