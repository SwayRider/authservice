// reset_password_tokens.go implements password reset token storage.
//
// Password reset tokens are short-lived (30 minutes by default) and allow
// users to set a new password without knowing their current password.
// Only one reset token is allowed per user at a time.

package db

import (
	"context"
	"database/sql"

	"github.com/swayrider/authservice/internal/model"
	log "github.com/swayrider/swlib/logger"
)

// CreateResetPasswordToken creates a new password reset token for a user.
// Any existing reset token for the user is deleted first.
func (d *DB) CreateResetPasswordToken(
	ctx context.Context,
	user *model.User,
) (*model.PasswordResetToken, error) {
	lg := d.lg.Derive(log.WithFunction("CreateResetPasswordToken"))

	if err := d.checkConnection(); err != nil {
		lg.Warnf("CreateResetPasswordToken: %v", err)
		return nil, err
	}

	err := d.DeleteResetPasswordToken(ctx, user.ID)
	if err != nil {
		lg.Errorf("failed to delete previous reset password tokens: %v", err)
		return nil, err
	}

	token, err := model.NewPasswordResetToken(user, model.DefaultPasswordResetTokenTTL)
	if err != nil {
		lg.Errorf("failed to create new reset password token: %v", err)
		return nil, err
	}

	_, err = d.ExecContext(ctx, `
		INSERT INTO reset_password_tokens (user_id, token, valid_until)
		VALUES ($1, $2, $3)
	`, token.UserId, token.Token, token.ValidUntil)
	if err != nil {
		lg.Errorf("failed to create new reset password token: %v", err)
		return nil, err
	}

	return token, nil
}

// GetResetPasswordToken retrieves the password reset token for a user.
// Returns ErrNoPasswordResetTokenFound if no token exists.
func (d *DB) GetResetPasswordToken(
	ctx context.Context,
	user *model.User,
) (*model.PasswordResetToken, error) {
	lg := d.lg.Derive(log.WithFunction("GetResetPasswordToken"))

	if err := d.checkConnection(); err != nil {
		lg.Warnf("GetResetPasswordToken: %v", err)
		return nil, err
	}

	var token model.PasswordResetToken
	err := d.QueryRowContext(ctx, `
		SELECT user_id, token, valid_until FROM reset_password_tokens
		WHERE user_id = $1
	`, user.ID).Scan(&token.UserId, &token.Token, &token.ValidUntil)
	if err != nil {
		if err == sql.ErrNoRows {
			lg.Debugf("no reset password token found for user: %s", user.ID)
			return nil, ErrNoPasswordResetTokenFound
		}
		lg.Errorf("failed to retrieve reset password token: %v", err)
		return nil, err
	}
	return &token, nil
}

// DeleteResetPasswordToken removes a user's password reset token.
// Called after successful password reset.
func (d *DB) DeleteResetPasswordToken(
	ctx context.Context,
	userId string,
) error {
	lg := d.lg.Derive(log.WithFunction("DeleteResetPasswordToken"))

	if err := d.checkConnection(); err != nil {
		lg.Warnf("DeleteResetPasswordToken: %v", err)
		return err
	}

	_, err := d.ExecContext(ctx, `
		DELETE FROM reset_password_tokens
		WHERE user_id = $1
	`, userId)
	return err
}

// cleanupPasswordResetTokens removes all expired password reset tokens.
// Called by the database maintenance routine.
func (d *DB) cleanupPasswordResetTokens(
	ctx context.Context,
) error {
	_, err := d.ExecContext(ctx, `
		DELETE FROM reset_password_tokens
		WHERE valid_until < now()
		`)
	return err
}
