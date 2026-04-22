// verification.go implements email verification token storage.
//
// Verification tokens are used to confirm a user's email address after
// registration. Tokens are valid for 24 hours by default. Only one
// verification token is allowed per user at a time.

package db

import (
	"context"
	"database/sql"

	"github.com/swayrider/authservice/internal/model"
	log "github.com/swayrider/swlib/logger"
)

// CreateVerificationToken creates a new verification token
//
// Parameters:
//   - ctx: the context
//   - user: the user
//
// Returns:
//   - *model.VerificationToken: the verification token
//   - error: if the verification token could not be created
func (d *DB) CreateVerificationToken(
	ctx context.Context,
	user *model.User,
) (*model.VerificationToken, error) {
	lg := d.lg.Derive(log.WithFunction("CreateVerificationToken"))

	if err := d.checkConnection(); err != nil {
		lg.Warnf("CreateVerificationToken: %v", err)
		return nil, err
	}

	err := d.DeleteVerificationToken(ctx, user.ID)
	if err != nil {
		lg.Errorf("failed to delete previous verificaiton tokens: %v", err)
		return nil, err
	}

	token, err := model.NewVerificationToken(user, model.DefaultVerificationTokenTTL)
	if err != nil {
		lg.Errorf("failed to create new verificaiton token: %v", err)
		return nil, err
	}

	_, err = d.ExecContext(ctx, `
		INSERT INTO verification_tokens (user_id, token, valid_until)
		VALUES ($1, $2, $3)
	`, token.UserId, token.Token, token.ValidUntil)
	if err != nil {
		lg.Errorf("failed to store verification token: %v", err)
		return nil, err
	}
	return token, nil
}

// GetVerificationToken returns the verification token for the user
//
// Parameters:
//   - ctx: the context
//   - user: the user
//
// Returns:
//   - *model.VerificationToken: the verification token
//   - error: if the verification token could not be retrieved
func (d *DB) GetVerificationToken(
	ctx context.Context,
	user *model.User,
) (*model.VerificationToken, error) {
	lg := d.lg.Derive(log.WithFunction("GetVerificationToken"))

	if err := d.checkConnection(); err != nil {
		lg.Warnf("GetVerificationToken: %v", err)
		return nil, err
	}

	var vt model.VerificationToken
	err := d.QueryRowContext(ctx, `
		SELECT user_id, token, valid_until FROM verification_tokens
		WHERE user_id = $1
	`, user.ID).Scan(&vt.UserId, &vt.Token, &vt.ValidUntil)
	if err != nil {
		if err == sql.ErrNoRows {
			lg.Debugf("no verification token found for user: %s", user.ID)
			return nil, ErrNoVerificationTokenFound
		}
		lg.Errorf("failed to retrieve verification token: %v", err)
		return nil, err
	}
	return &vt, nil
}

// DeleteVerificationToken deletes the verification token for the user
func (d *DB) DeleteVerificationToken(
	ctx context.Context,
	userId string,
) error {
	lg := d.lg.Derive(log.WithFunction("DeleteVerificationToken"))

	if err := d.checkConnection(); err != nil {
		lg.Warnf("DeleteVerificationToken: %v", err)
		return err
	}

	_, err := d.ExecContext(ctx, `
		DELETE FROM verification_tokens
		WHERE user_id = $1
		`, userId)
	if err != nil {
		return err
	}
	return nil
}

// cleanupVerificationTokens deletes expired verification tokens
func (d *DB) cleanupVerificationTokens(
	ctx context.Context,
) error {
	_, err := d.ExecContext(ctx, `
		DELETE FROM verification_tokens
		WHERE valid_until < now()
		`)
	if err != nil {
		return err
	}
	return nil
}
