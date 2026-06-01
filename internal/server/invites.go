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
		if errors.Is(err, db.ErrUniqueViolation) {
			return nil, status.Errorf(
				codes.AlreadyExists, "invite for %s already exists", req.Email)
		}
		lg.Errorf("failed to create invite for %s: %v", req.Email, err)
		return nil, status.Errorf(codes.Internal, "failed to create invite")
	}

	go s.sendInviteEmail(req.Email)

	return &authv1.InviteUserResponse{
		Message: fmt.Sprintf("Invitation created for %s", req.Email),
	}, nil
}

// RevokeInvite removes an email address from the registration invite list.
func (s *AuthServer) RevokeInvite(
	ctx context.Context,
	req *authv1.RevokeInviteRequest,
) (*authv1.RevokeInviteResponse, error) {
	lg := s.Logger().Derive(log.WithFunction("RevokeInvite"))

	if req.Email == "" {
		return nil, status.Errorf(codes.InvalidArgument, "email is required")
	}

	if err := s.DB().DeleteInvite(ctx, req.Email); err != nil {
		lg.Errorf("failed to revoke invite for %s: %v", req.Email, err)
		return nil, status.Errorf(codes.Internal, "failed to revoke invite")
	}

	return &authv1.RevokeInviteResponse{
		Message: fmt.Sprintf("Invitation revoked for %s", req.Email),
	}, nil
}

// ListInvites returns a paginated list of pending registration invites.
func (s *AuthServer) ListInvites(
	ctx context.Context,
	req *authv1.ListInvitesRequest,
) (*authv1.ListInvitesResponse, error) {
	lg := s.Logger().Derive(log.WithFunction("ListInvites"))

	page := int(req.Page)
	pageSize := int(req.PageSize)
	if page < 0 {
		page = 0
	}
	if pageSize < 0 {
		pageSize = 0
	}

	count, err := s.DB().CountInvites(ctx)
	if err != nil {
		lg.Errorf("failed to count invites: %v", err)
		return nil, status.Errorf(codes.Internal, "failed to list invites")
	}

	invites, err := s.DB().ListInvites(ctx, page, pageSize)
	if err != nil {
		lg.Errorf("failed to list invites: %v", err)
		return nil, status.Errorf(codes.Internal, "failed to list invites")
	}

	protoInvites := make([]*authv1.ListInvitesResponse_Invite, 0, len(invites))
	for _, inv := range invites {
		protoInvites = append(protoInvites, &authv1.ListInvitesResponse_Invite{
			Id:        inv.ID,
			Email:     inv.Email,
			CreatedAt: timestamppb.New(inv.CreatedAt),
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
