package server

import (
	"context"
	"time"

	"github.com/swayrider/authservice/internal/db"
	"github.com/swayrider/authservice/internal/model"
)

// Database abstracts all persistence operations used by the server handlers.
// This allows handlers to be tested with a mock without a real PostgreSQL connection.
type Database interface {
	// User operations
	AdminExists(ctx context.Context) (bool, error)
	CreateAdminUser(ctx context.Context, email, hashedPassword string) (string, error)
	RegisterUser(ctx context.Context, email, hashedPassword string) (string, error)
	GetUserByEmail(ctx context.Context, email string) (*model.UserInternal, error)
	GetUserByID(ctx context.Context, id string) (*model.UserInternal, error)
	MarkUserVerified(ctx context.Context, userId string) error
	UpdatePassword(ctx context.Context, userId, hashedPassword string) error
	ChangeAccountLevel(ctx context.Context, userId, accountLevel string) error

	// Refresh token operations
	CreateRefreshToken(ctx context.Context, user *model.User, jwtID, ip, userAgent string) (*model.RefreshToken, error)
	ConsumeRefreshToken(ctx context.Context, token string) (*model.RefreshToken, error)
	DeleteRefreshToken(ctx context.Context, token string) error
	DeleteRefreshTokensByUserID(ctx context.Context, userId string) error

	// Verification token operations
	CreateVerificationToken(ctx context.Context, user *model.User) (*model.VerificationToken, error)
	GetVerificationToken(ctx context.Context, user *model.User) (*model.VerificationToken, error)
	DeleteVerificationToken(ctx context.Context, userId string) error

	// Password reset token operations
	CreateResetPasswordToken(ctx context.Context, user *model.User) (*model.PasswordResetToken, error)
	GetResetPasswordToken(ctx context.Context, user *model.User) (*model.PasswordResetToken, error)
	DeleteResetPasswordToken(ctx context.Context, userId string) error

	// JWT key operations
	GetSigningKey(ctx context.Context) (string, error)
	GetVerificationKeys(ctx context.Context) ([]string, error)

	// Service client operations
	CreateServiceClient(ctx context.Context, name, description string, scopes []string, secretHash string) (string, error)
	DeleteServiceClient(ctx context.Context, clientId string) error
	GetServiceClientByID(ctx context.Context, clientID string) (*model.ServiceClientInternal, error)
	CountServiceClients(ctx context.Context) (int, error)
	ListServiceClients(ctx context.Context, page, pageSize int) ([]model.ServiceClient, error)

	// Invite operations
	CreateInvite(ctx context.Context, email string) (string, error)
	DeleteInvite(ctx context.Context, email string) error
	ConsumeInvite(ctx context.Context, email string) error
	ReInvite(ctx context.Context, email string) error
	GetInviteByEmail(ctx context.Context, email string) (*model.Invite, error)
	IsEmailInvited(ctx context.Context, email string) (bool, error)
	CountInvites(ctx context.Context, registered *bool) (int, error)
	ListInvites(ctx context.Context, page, pageSize int, registered *bool) ([]model.Invite, error)

	// Security throttle operations (account lockout, email cooldown)
	IsAttemptLocked(ctx context.Context, scope db.ThrottleScope, identifier string) (bool, error)
	RecordAttemptResult(ctx context.Context, scope db.ThrottleScope, identifier string, success bool, maxAttempts int, window, lockoutDuration time.Duration) (bool, error)
	TryConsumeEmailCooldown(ctx context.Context, scope db.ThrottleScope, identifier string, cooldown time.Duration) (bool, error)

	// Audit logging
	InsertAuditEvent(ctx context.Context, ev db.AuditEvent) error
}
