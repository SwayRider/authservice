// invites.go implements the registration invite list storage.
//
// In INVITE_ONLY mode, an admin must pre-approve an email address before
// that address can register. Invite records are kept permanently; the
// registered column is set to true after a successful registration.

package db

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/swayrider/authservice/internal/model"
	log "github.com/swayrider/swlib/logger"
)

// CreateInvite adds an email address to the registration invite list.
// Returns ErrUniqueViolation if an invite for that email already exists.
func (d *DB) CreateInvite(
	ctx context.Context,
	email string,
) (id string, err error) {
	lg := d.lg.Derive(log.WithFunction("CreateInvite"))

	if err = d.checkConnection(); err != nil {
		lg.Errorf("failed to check connection: %v", err)
		return
	}

	id = uuid.NewString()
	_, err = d.ExecContext(ctx, `
		INSERT INTO registration_invites (id, email) VALUES ($1, $2)
	`, id, email)
	if err != nil {
		if pqErr, ok := err.(*pq.Error); ok {
			if pqErr.Code.Name() == "unique_violation" {
				return "", ErrUniqueViolation
			}
		}
		lg.Errorf("failed to create invite for %s: %v", email, err)
		return
	}

	return
}

// DeleteInvite removes an invite by email address.
// It is a no-op if no invite exists for that email.
func (d *DB) DeleteInvite(
	ctx context.Context,
	email string,
) error {
	lg := d.lg.Derive(log.WithFunction("DeleteInvite"))

	if err := d.checkConnection(); err != nil {
		lg.Errorf("failed to check connection: %v", err)
		return err
	}

	_, err := d.ExecContext(ctx, `
		DELETE FROM registration_invites WHERE email = $1
	`, email)
	if err != nil {
		lg.Errorf("failed to delete invite for %s: %v", email, err)
		return err
	}
	return nil
}

// ConsumeInvite marks an invite as registered after a successful registration.
// It is a no-op if no invite exists for that email.
func (d *DB) ConsumeInvite(
	ctx context.Context,
	email string,
) error {
	lg := d.lg.Derive(log.WithFunction("ConsumeInvite"))

	if err := d.checkConnection(); err != nil {
		lg.Errorf("failed to check connection: %v", err)
		return err
	}

	_, err := d.ExecContext(ctx, `
		UPDATE registration_invites SET registered = true WHERE email = $1
	`, email)
	if err != nil {
		lg.Errorf("failed to consume invite for %s: %v", email, err)
		return err
	}
	return nil
}

// ReInvite resets a previously-registered invite back to registered=false,
// allowing a user whose account was deleted to re-register.
// Returns ErrInviteNotFound if no invite exists for that email.
func (d *DB) ReInvite(
	ctx context.Context,
	email string,
) error {
	lg := d.lg.Derive(log.WithFunction("ReInvite"))

	if err := d.checkConnection(); err != nil {
		lg.Errorf("failed to check connection: %v", err)
		return err
	}

	res, err := d.ExecContext(ctx, `
		UPDATE registration_invites SET registered = false WHERE email = $1
	`, email)
	if err != nil {
		lg.Errorf("failed to re-invite %s: %v", email, err)
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrInviteNotFound
	}
	return nil
}

// GetInviteByEmail returns the invite record for the given email address.
// Returns ErrInviteNotFound if no invite exists for that email.
func (d *DB) GetInviteByEmail(
	ctx context.Context,
	email string,
) (*model.Invite, error) {
	lg := d.lg.Derive(log.WithFunction("GetInviteByEmail"))

	if err := d.checkConnection(); err != nil {
		lg.Errorf("failed to check connection: %v", err)
		return nil, err
	}

	var inv model.Invite
	err := d.QueryRowContext(ctx, `
		SELECT id, email, created_at, registered
		FROM registration_invites
		WHERE email = $1
	`, email).Scan(&inv.ID, &inv.Email, &inv.CreatedAt, &inv.Registered)
	if err == sql.ErrNoRows {
		return nil, ErrInviteNotFound
	}
	if err != nil {
		lg.Errorf("failed to get invite for %s: %v", email, err)
		return nil, err
	}
	return &inv, nil
}

// IsEmailInvited reports whether a non-registered invite exists for the given email.
func (d *DB) IsEmailInvited(
	ctx context.Context,
	email string,
) (bool, error) {
	lg := d.lg.Derive(log.WithFunction("IsEmailInvited"))

	if err := d.checkConnection(); err != nil {
		lg.Errorf("failed to check connection: %v", err)
		return false, err
	}

	var count int
	err := d.QueryRowContext(ctx, `
		SELECT COUNT(1) FROM registration_invites WHERE email = $1 AND registered = false
	`, email).Scan(&count)
	if err != nil {
		lg.Errorf("failed to check invite for %s: %v", email, err)
		return false, err
	}
	return count > 0, nil
}

// CountInvites returns the total number of invites, optionally filtered by
// registration status. Pass nil to count all invites.
func (d *DB) CountInvites(
	ctx context.Context,
	registered *bool,
) (count int, err error) {
	lg := d.lg.Derive(log.WithFunction("CountInvites"))

	if err = d.checkConnection(); err != nil {
		lg.Errorf("failed to check connection: %v", err)
		return
	}

	query := `SELECT COUNT(*) FROM registration_invites`
	if registered != nil {
		query = fmt.Sprintf("%s WHERE registered = %t", query, *registered)
	}
	err = d.QueryRowContext(ctx, query).Scan(&count)
	return
}

// ListInvites returns a paginated list of invites ordered by creation time.
// Pass nil for registered to return all invites; false for pending only;
// true for registered only. If page or pageSize is 0, all results are returned.
func (d *DB) ListInvites(
	ctx context.Context,
	page, pageSize int,
	registered *bool,
) (invites []model.Invite, err error) {
	where := ""
	if registered != nil {
		where = fmt.Sprintf(" WHERE registered = %t", *registered)
	}

	base := `SELECT id, email, created_at, registered FROM registration_invites` + where

	var rows *sql.Rows
	if page == 0 || pageSize == 0 {
		rows, err = d.QueryContext(ctx, base+` ORDER BY created_at DESC`)
	} else {
		rows, err = d.QueryContext(ctx,
			base+` ORDER BY created_at DESC LIMIT $1 OFFSET $2`,
			pageSize, (page-1)*pageSize)
	}
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var inv model.Invite
		if err = rows.Scan(&inv.ID, &inv.Email, &inv.CreatedAt, &inv.Registered); err != nil {
			return nil, err
		}
		invites = append(invites, inv)
	}

	return
}
