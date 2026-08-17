package server

import (
	"context"
	"fmt"
	"testing"

	"github.com/swayrider/authservice/internal/db"
	"github.com/swayrider/authservice/internal/model"
	authv1 "github.com/swayrider/protos/auth/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// =============================================================================
// InviteUser Tests
// =============================================================================

func TestInviteUser_NewEmail_Succeeds(t *testing.T) {
	mdb := &mockDB{
		createInviteFn: func(_ context.Context, _ string) (string, error) {
			return "invite-id", nil
		},
	}
	mail := newRecordingMailSender()
	srv := newTestServer(mdb, mail)
	ctx := context.Background()

	resp, err := srv.InviteUser(ctx, &authv1.InviteUserRequest{Email: "new@example.com"})
	if err != nil {
		t.Fatalf("InviteUser failed: %v", err)
	}
	if resp.Message == "" {
		t.Error("expected a non-empty message")
	}
	mail.waitForSend(t)
}

func TestInviteUser_EmptyEmail_ReturnsInvalidArgument(t *testing.T) {
	srv := newTestServer(&mockDB{}, &noopMailSender{})
	ctx := context.Background()

	_, err := srv.InviteUser(ctx, &authv1.InviteUserRequest{Email: ""})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("code = %v, want %v", st.Code(), codes.InvalidArgument)
	}
}

// TestInviteUser_PendingVsAlreadyRegistered_ReturnUniformMessage is the
// regression test for the enumeration fix: re-inviting an email with a
// still-pending invite and re-inviting an email that already has an active
// account must be indistinguishable from the caller's perspective.
func TestInviteUser_PendingVsAlreadyRegistered_ReturnUniformMessage(t *testing.T) {
	pendingMdb := &mockDB{
		createInviteFn: func(_ context.Context, _ string) (string, error) {
			return "", db.ErrUniqueViolation
		},
		getInviteByEmailFn: func(_ context.Context, email string) (*model.Invite, error) {
			return &model.Invite{Email: email, Registered: false}, nil
		},
	}
	registeredMdb := &mockDB{
		createInviteFn: func(_ context.Context, _ string) (string, error) {
			return "", db.ErrUniqueViolation
		},
		getInviteByEmailFn: func(_ context.Context, email string) (*model.Invite, error) {
			return &model.Invite{Email: email, Registered: true}, nil
		},
		getUserByEmailFn: func(_ context.Context, email string) (*model.UserInternal, error) {
			u := testUser()
			u.Email = email
			return u, nil
		},
	}

	ctx := context.Background()
	pendingSrv := newTestServer(pendingMdb, &noopMailSender{})
	_, pendingErr := pendingSrv.InviteUser(ctx, &authv1.InviteUserRequest{Email: "pending@example.com"})
	registeredSrv := newTestServer(registeredMdb, &noopMailSender{})
	_, registeredErr := registeredSrv.InviteUser(ctx, &authv1.InviteUserRequest{Email: "registered@example.com"})

	pendingSt, _ := status.FromError(pendingErr)
	registeredSt, _ := status.FromError(registeredErr)

	if pendingSt.Code() != codes.AlreadyExists {
		t.Errorf("pending invite code = %v, want %v", pendingSt.Code(), codes.AlreadyExists)
	}
	if registeredSt.Code() != codes.AlreadyExists {
		t.Errorf("already-registered code = %v, want %v", registeredSt.Code(), codes.AlreadyExists)
	}

	const wantMsg = "registration for %s is already pending or complete"
	if pendingSt.Message() != fmt.Sprintf(wantMsg, "pending@example.com") {
		t.Errorf("pending message = %q", pendingSt.Message())
	}
	if registeredSt.Message() != fmt.Sprintf(wantMsg, "registered@example.com") {
		t.Errorf("already-registered message = %q", registeredSt.Message())
	}
}

func TestInviteUser_AccountDeleted_ResetsInvite(t *testing.T) {
	reInviteCalled := false
	mdb := &mockDB{
		createInviteFn: func(_ context.Context, _ string) (string, error) {
			return "", db.ErrUniqueViolation
		},
		getInviteByEmailFn: func(_ context.Context, email string) (*model.Invite, error) {
			return &model.Invite{Email: email, Registered: true}, nil
		},
		getUserByEmailFn: func(_ context.Context, _ string) (*model.UserInternal, error) {
			return nil, db.ErrUserNotFound
		},
		reInviteFn: func(_ context.Context, _ string) error {
			reInviteCalled = true
			return nil
		},
	}
	mail := newRecordingMailSender()
	srv := newTestServer(mdb, mail)
	ctx := context.Background()

	_, err := srv.InviteUser(ctx, &authv1.InviteUserRequest{Email: "deleted@example.com"})
	if err != nil {
		t.Fatalf("InviteUser failed: %v", err)
	}
	if !reInviteCalled {
		t.Error("expected ReInvite to be called when the account was deleted")
	}
	mail.waitForSend(t)
}

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
