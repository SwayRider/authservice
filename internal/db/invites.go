// invites.go implements the registration invite list storage.
//
// In INVITE_ONLY mode, an admin must pre-approve an email address before
// that address can register. Invite records are consumed (deleted) after
// a successful registration.

package db

import (
	"context"
	"database/sql"

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

// ConsumeInvite removes an invite after a successful registration.
// It is a no-op if no invite exists for that email.
func (d *DB) ConsumeInvite(
	ctx context.Context,
	email string,
) error {
	return d.DeleteInvite(ctx, email)
}

// IsEmailInvited reports whether an invite exists for the given email.
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
		SELECT COUNT(1) FROM registration_invites WHERE email = $1
	`, email).Scan(&count)
	if err != nil {
		lg.Errorf("failed to check invite for %s: %v", email, err)
		return false, err
	}
	return count > 0, nil
}

// CountInvites returns the total number of pending invites.
func (d *DB) CountInvites(
	ctx context.Context,
) (count int, err error) {
	lg := d.lg.Derive(log.WithFunction("CountInvites"))

	if err = d.checkConnection(); err != nil {
		lg.Errorf("failed to check connection: %v", err)
		return
	}

	err = d.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM registration_invites
	`).Scan(&count)
	return
}

// ListInvites returns a paginated list of pending invites ordered by creation time.
// If page or pageSize is 0, all invites are returned without pagination.
func (d *DB) ListInvites(
	ctx context.Context,
	page, pageSize int,
) (invites []model.Invite, err error) {
	var rows *sql.Rows
	if page == 0 || pageSize == 0 {
		rows, err = d.QueryContext(ctx, `
			SELECT id, email, created_at FROM registration_invites
			ORDER BY created_at DESC
		`)
	} else {
		rows, err = d.QueryContext(ctx, `
			SELECT id, email, created_at FROM registration_invites
			ORDER BY created_at DESC
			LIMIT $1 OFFSET $2
		`, pageSize, (page-1)*pageSize)
	}
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var inv model.Invite
		if err = rows.Scan(&inv.ID, &inv.Email, &inv.CreatedAt); err != nil {
			return nil, err
		}
		invites = append(invites, inv)
	}

	return
}
