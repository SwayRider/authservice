// user.go implements user account storage and management.
//
// This file provides CRUD operations for user accounts including:
//   - User registration (regular users and admins)
//   - User lookup by ID or email
//   - Account status updates (verification, password, account level)

package db

import (
	"context"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/swayrider/authservice/internal/model"
	log "github.com/swayrider/swlib/logger"
)

// AdminExists returns true if an admin user exists
//
// Parameters:
//   - ctx: the context
//
// Returns:
//   - bool: true if an admin user exists
//   - error: if the query could not be executed
func (d *DB) AdminExists(ctx context.Context) (bool, error) {
	lg := d.lg.Derive(log.WithFunction("AdminExists"))

	if err := d.checkConnection(); err != nil {
		lg.Errorf("failed to check connection: %v", err)
		return false, err
	}

	var count int
	err := d.QueryRowContext(ctx, `
		SELECT COUNT(1) FROM users WHERE is_admin = true
	`).Scan(&count)
	if err != nil {
		lg.Warnf("failed to verify admin: %v", err)
	}
	lg.Debugf("number of administrators: %v", count)
	return count > 0, err
}

// CreateAdminUser creates an admin user
//
// Parameters:
//   - ctx: the context
//   - email: the email of the admin user
//   - plainPassword: the password of the admin user
//
// Returns:
//   - error: if the query could not be executed
func (d *DB) CreateAdminUser(
	ctx context.Context,
	email, hashedPassword string,
) (userId string, err error) {
	lg := d.lg.Derive(log.WithFunction("CreateAdminUser"))

	if err := d.checkConnection(); err != nil {
		lg.Warnf("CreateAdminUser: %v", err)
		return "", err
	}

	id := uuid.NewString()
	_, err = d.ExecContext(ctx, `
		INSERT INTO users (id, email, password_hash, is_verified, is_admin, account_level)
		VALUES ($1, $2, $3, true, true, 'premium')
	`, id, email, hashedPassword)
	if err != nil {
		if pqErr, ok := err.(*pq.Error); ok {
			if pqErr.Code.Name() == "unique_violation" {
				lg.Errorf("email address already in use: %v", err)
				return "", ErrUniqueViolation
			}
		}
		lg.Errorf("failed to create admin user: %v", err)
		return "", err
	}
	return id, err
}

// RegisterUser registers a new user
//
// Parameters:
//   - ctx: the context
//   - email: the email of the user
//   - plainPassword: the password of the user
//
// Returns:
//   - string: the id of the user
//   - error: if the user could not be registered
func (d *DB) RegisterUser(
	ctx context.Context,
	email, hashedPassword string,
) (userId string, err error) {
	lg := d.lg.Derive(log.WithFunction("RegisterUser"))

	if err := d.checkConnection(); err != nil {
		lg.Warnf("RegisterUser: %v", err)
		return "", err
	}

	id := uuid.NewString()
	_, err = d.ExecContext(ctx, `
		INSERT INTO users (id, email, password_hash, is_verified, is_admin, account_level)
		VALUES ($1, $2, $3, false, false, 'free')
	`, id, email, hashedPassword)
	if err != nil {
		if pqErr, ok := err.(*pq.Error); ok {
			if pqErr.Code.Name() == "unique_violation" {
				lg.Errorf("eamil address already in use: %v", err)
				return "", ErrUniqueViolation
			}
		}
		lg.Errorf("failed to register new user with email: '%s': %v", email, err)
		return "", err
	}
	return id, nil
}

// GetUserByEmail returns the user with the given email
//
// Parameters:
//   - ctx: the context
//   - email: the email of the user
//
// Returns:
//   - *model.UserInternal: the user
//   - error: if the user could not be retrieved
func (d *DB) GetUserByEmail(
	ctx context.Context,
	email string,
) (*model.UserInternal, error) {
	lg := d.lg.Derive(log.WithFunction("GetUserByEmail"))

	if err := d.checkConnection(); err != nil {
		lg.Warnf("GetUserByEmail: %v", err)
		return nil, err
	}

	var u model.UserInternal
	err := d.QueryRowContext(ctx, `
		SELECT
			id, email, password_hash,
			provider, provider_id,
			is_verified, is_admin, account_level,
			created_at, updated_at
		FROM users
		WHERE email = $1
	`, email).Scan(
		&u.ID, &u.Email, &u.PasswordHash,
		&u.Provider, &u.ProviderID,
		&u.IsVerified, &u.IsAdmin, &u.AccountLevel,
		&u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		lg.Warnf("failed to retrieve user with email: '%s': %v", email, err)
		return nil, ErrUserNotFound
	}
	return &u, nil
}

// GetUserByID returns the user with the given id
//
// Parameters:
//   - ctx: the context
//   - id: the id of the user
//
// Returns:
//   - *model.UserInternal: the user
//   - error: if the user could not be retrieved
func (d *DB) GetUserByID(
	ctx context.Context,
	id string,
) (*model.UserInternal, error) {
	lg := d.lg.Derive(log.WithFunction("GetUserByID"))

	if err := d.checkConnection(); err != nil {
		lg.Warnf("GetUserByID: %v", err)
		return nil, err
	}

	var u model.UserInternal
	err := d.QueryRowContext(ctx, `
		SELECT
			id, email, password_hash,
			provider, provider_id,
			is_verified, is_admin, account_level,
			created_at, updated_at
		FROM users
		WHERE id = $1
	`, id).Scan(
		&u.ID, &u.Email, &u.PasswordHash,
		&u.Provider, &u.ProviderID,
		&u.IsVerified, &u.IsAdmin, &u.AccountLevel,
		&u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		lg.Warnf("failed to retrieve user with id: '%s': %v", id, err)
		return nil, ErrUserNotFound
	}
	return &u, nil
}

// MarkUserVerified sets the user's is_verified flag to true.
// Called after successful email verification.
func (d *DB) MarkUserVerified(
	ctx context.Context,
	userId string,
) error {
	lg := d.lg.Derive(log.WithFunction("MarkUserVerified"))

	if err := d.checkConnection(); err != nil {
		lg.Warnf("MarkUserVerified: %v", err)
		return err
	}

	_, err := d.ExecContext(ctx, `
		UPDATE users
		SET
			is_verified = true,
			updated_at = now()
		WHERE id = $1
	`, userId)
	if err != nil {
		lg.Warnf("failed to mark user as verified: %v", err)
		return err
	}
	return nil
}

// UpdatePassword updates a user's password hash.
// The password should already be hashed before calling this function.
func (d *DB) UpdatePassword(
	ctx context.Context,
	userId string,
	hashedPassword string,
) error {
	lg := d.lg.Derive(log.WithFunction("UpdatePassword"))

	if err := d.checkConnection(); err != nil {
		lg.Warnf("UpdatePassword: %v", err)
		return err
	}

	_, err := d.ExecContext(ctx, `
		UPDATE users
		SET
			password_hash = $2,
			updated_at = now()
		WHERE id = $1
	`, userId, hashedPassword)
	if err != nil {
		lg.Warnf("failed to update password: %v", err)
		return err
	}
	return nil
}

// ChangeAccountLevel updates a user's account level (e.g., "free", "premium").
// This is typically called by admin users to manage subscriptions.
func (d *DB) ChangeAccountLevel(
	ctx context.Context,
	userId string,
	accountLevel string,
) error {
	lg := d.lg.Derive(log.WithFunction("ChageAccountLevel"))

	if err := d.checkConnection(); err != nil {
		lg.Warnf("ChangeAccountLevel: %v", err)
		return err
	}

	_, err := d.ExecContext(ctx, `
		UPDATE users
		SET
			account_level = $2,
			updated_at = now()
		WHERE id = $1
	`, userId, accountLevel)
	if err != nil {
		lg.Warnf("failed to update account level: %v", err)
		return err
	}
	return nil
}
