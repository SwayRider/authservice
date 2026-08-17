package server

import (
	"context"
	"testing"

	authv1 "github.com/swayrider/protos/auth/v1"
	"github.com/swayrider/authservice/internal/model"
)

// =============================================================================
// ListInvites Tests
// =============================================================================

func TestListInvites_PaginationDefaults(t *testing.T) {
	var calledPage, calledPageSize int

	mdb := &mockDB{
		listInvitesFn: func(_ context.Context, page, pageSize int, _ *bool) ([]model.Invite, error) {
			calledPage = page
			calledPageSize = pageSize
			return nil, nil
		},
	}
	srv := newTestServer(mdb, &noopMailSender{})
	ctx := context.Background()

	// page < 0 should be clamped to 1; pageSize < 0 should be clamped to 10 --
	// matching ListServiceClients' defaults, not the old "0 means return
	// everything" behavior.
	_, err := srv.ListInvites(ctx, &authv1.ListInvitesRequest{
		Page:     -1,
		PageSize: -1,
	})
	if err != nil {
		t.Fatalf("ListInvites failed: %v", err)
	}
	if calledPage != 1 {
		t.Errorf("ListInvites called with page=%d, want 1", calledPage)
	}
	if calledPageSize != 10 {
		t.Errorf("ListInvites called with pageSize=%d, want 10", calledPageSize)
	}
}
