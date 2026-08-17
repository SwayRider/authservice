// invites.go implements invite management endpoints.
//
// In INVITE_ONLY registration mode an admin must add an email address to the
// invite list before the owner of that address can register. These endpoints
// are restricted to admin users only.

package server

import (
	"context"
	"errors"
	"fmt"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
	"github.com/swayrider/grpcclients/mailclient"
	authv1 "github.com/swayrider/protos/auth/v1"
	"github.com/swayrider/authservice/internal/db"
	log "github.com/swayrider/swlib/logger"
)

// InviteUser adds an email address to the registration invite list and sends
// an invitation email to that address.
//
// If an invite already exists for the email and the user has not yet registered,
// AlreadyExists is returned. If the user has registered but their account was
// subsequently deleted, the invite is reset so they can re-register.
func (s *AuthServer) InviteUser(
	ctx context.Context,
	req *authv1.InviteUserRequest,
) (*authv1.InviteUserResponse, error) {
	lg := s.Logger().Derive(log.WithFunction("InviteUser"))

	if req.Email == "" {
		return nil, status.Errorf(codes.InvalidArgument, "email is required")
	}

	_, err := s.DB().CreateInvite(ctx, req.Email)
	if err != nil {
		if !errors.Is(err, db.ErrUniqueViolation) {
			lg.Errorf("failed to create invite for %s: %v", req.Email, err)
			return nil, status.Errorf(codes.Internal, "failed to create invite")
		}

		// Invite already exists — check whether re-invitation is allowed.
		inv, fetchErr := s.DB().GetInviteByEmail(ctx, req.Email)
		if fetchErr != nil {
			lg.Errorf("failed to fetch invite for %s: %v", req.Email, fetchErr)
			return nil, status.Errorf(codes.Internal, "failed to create invite")
		}
		if !inv.Registered {
			return nil, status.Errorf(
				codes.AlreadyExists, "invite for %s already exists", req.Email)
		}

		// Invite was consumed — allow re-invitation only if the account is gone.
		_, userErr := s.DB().GetUserByEmail(ctx, req.Email)
		if userErr == nil {
			return nil, status.Errorf(
				codes.AlreadyExists, "user %s already has an active account", req.Email)
		}
		if !errors.Is(userErr, db.ErrUserNotFound) {
			lg.Errorf("failed to look up user %s: %v", req.Email, userErr)
			return nil, status.Errorf(codes.Internal, "failed to create invite")
		}

		// Account deleted — reset the invite so the user can re-register.
		if resetErr := s.DB().ReInvite(ctx, req.Email); resetErr != nil {
			lg.Errorf("failed to reset invite for %s: %v", req.Email, resetErr)
			return nil, status.Errorf(codes.Internal, "failed to re-invite")
		}
	}

	go s.sendInviteEmail(req.Email)

	return &authv1.InviteUserResponse{
		Message: fmt.Sprintf("Invitation created for %s", req.Email),
	}, nil
}

// RevokeInvite removes an email address from the registration invite list.
// Returns FailedPrecondition if the invitee has already registered.
func (s *AuthServer) RevokeInvite(
	ctx context.Context,
	req *authv1.RevokeInviteRequest,
) (*authv1.RevokeInviteResponse, error) {
	lg := s.Logger().Derive(log.WithFunction("RevokeInvite"))

	if req.Email == "" {
		return nil, status.Errorf(codes.InvalidArgument, "email is required")
	}

	inv, err := s.DB().GetInviteByEmail(ctx, req.Email)
	if err != nil {
		if errors.Is(err, db.ErrInviteNotFound) {
			return &authv1.RevokeInviteResponse{
				Message: fmt.Sprintf("No invite found for %s", req.Email),
			}, nil
		}
		lg.Errorf("failed to fetch invite for %s: %v", req.Email, err)
		return nil, status.Errorf(codes.Internal, "failed to revoke invite")
	}

	if inv.Registered {
		return nil, status.Errorf(
			codes.FailedPrecondition,
			"cannot revoke invite for %s: user has already registered", req.Email)
	}

	if err := s.DB().DeleteInvite(ctx, req.Email); err != nil {
		lg.Errorf("failed to revoke invite for %s: %v", req.Email, err)
		return nil, status.Errorf(codes.Internal, "failed to revoke invite")
	}

	return &authv1.RevokeInviteResponse{
		Message: fmt.Sprintf("Invitation revoked for %s", req.Email),
	}, nil
}

// Pagination defaults shared by ListInvites and ListServiceClients.
const (
	defaultPage     = 1
	defaultPageSize = 10
)

// ListInvites returns a paginated list of registration invites.
// When req.Registered is set, only invites matching that status are returned.
func (s *AuthServer) ListInvites(
	ctx context.Context,
	req *authv1.ListInvitesRequest,
) (*authv1.ListInvitesResponse, error) {
	lg := s.Logger().Derive(log.WithFunction("ListInvites"))

	page := int(req.Page)
	pageSize := int(req.PageSize)
	if page < 0 {
		page = defaultPage
	}
	if pageSize < 0 {
		pageSize = defaultPageSize
	}

	count, err := s.DB().CountInvites(ctx, req.Registered)
	if err != nil {
		lg.Errorf("failed to count invites: %v", err)
		return nil, status.Errorf(codes.Internal, "failed to list invites")
	}

	invites, err := s.DB().ListInvites(ctx, page, pageSize, req.Registered)
	if err != nil {
		lg.Errorf("failed to list invites: %v", err)
		return nil, status.Errorf(codes.Internal, "failed to list invites")
	}

	protoInvites := make([]*authv1.ListInvitesResponse_Invite, 0, len(invites))
	for _, inv := range invites {
		registered := inv.Registered
		protoInvites = append(protoInvites, &authv1.ListInvitesResponse_Invite{
			Id:         inv.ID,
			Email:      inv.Email,
			CreatedAt:  timestamppb.New(inv.CreatedAt),
			Registered: &registered,
		})
	}

	return &authv1.ListInvitesResponse{
		Invites:    protoInvites,
		NumInvites: int32(count),
	}, nil
}

// sendInviteEmail sends an invitation email to the given address.
// It runs asynchronously; errors are logged but not returned.
func (s *AuthServer) sendInviteEmail(email string) {
	lg := s.Logger().Derive(log.WithFunction("sendInviteEmail"))

	_, err := s.mailClient.SendTemplateInternal(
		mailclient.NewTemplateMail(
			s.mailerAddress, []string{email}, nil, nil,
			"SwayRider - You're invited",
			"invite_user.html", "invite_user.txt",
			map[string]string{
				"Email":           email,
				"RegistrationURL": s.registrationUrl,
				"Year":            fmt.Sprintf("%d", time.Now().Year()),
			}))
	if err != nil {
		lg.Errorf("failed to send invite email to %s: %v", email, err)
	}
}
