// mfa_reset.go implements email-verified MFA/TOTP reset token storage.
//
// An MFA reset token pairs a random, emailed token with a freshly generated,
// not-yet-active TOTP secret (encrypted the same way as user_mfa.secret --
// see encryptSecret/decryptSecret in mfa.go). Only one reset token is
// allowed per user at a time, mirroring reset_password_tokens.go.

package db

import (
	"context"
	"database/sql"

	"github.com/swayrider/authservice/internal/model"
	log "github.com/swayrider/swlib/logger"
)

// CreateMFAResetToken creates a new MFA reset token for userID, storing
// pendingSecret encrypted the same way as a user_mfa row. Any existing reset
// token for the user is deleted first.
func (d *DB) CreateMFAResetToken(
	ctx context.Context,
	userID, pendingSecret string,
) (*model.MFAResetToken, error) {
	lg := d.lg.Derive(log.WithFunction("CreateMFAResetToken"))

	if err := d.checkConnection(); err != nil {
		lg.Warnf("CreateMFAResetToken: %v", err)
		return nil, err
	}

	if err := d.DeleteMFAResetToken(ctx, userID); err != nil {
		lg.Errorf("failed to delete previous MFA reset token: %v", err)
		return nil, err
	}

	token, err := model.NewMFAResetToken(userID, pendingSecret, model.DefaultMFAResetTokenTTL)
	if err != nil {
		lg.Errorf("failed to create new MFA reset token: %v", err)
		return nil, err
	}

	storedSecret, keyID, err := encryptSecret(pendingSecret, d.keyRing)
	if err != nil {
		lg.Errorf("CreateMFAResetToken: %v", err)
		return nil, err
	}

	_, err = d.ExecContext(ctx, `
		INSERT INTO mfa_reset_tokens (user_id, token, pending_secret, pending_secret_key_id, valid_until)
		VALUES ($1, $2, $3, $4, $5)
	`, token.UserId, token.Token, storedSecret,
		sql.NullString{String: keyID, Valid: keyID != ""}, token.ValidUntil)
	if err != nil {
		lg.Errorf("failed to create new MFA reset token: %v", err)
		return nil, err
	}

	return token, nil
}

// GetMFAResetToken retrieves the MFA reset token for a user, with the
// pending secret decrypted. Returns ErrNoMFAResetTokenFound if no token
// exists.
func (d *DB) GetMFAResetToken(ctx context.Context, userID string) (*model.MFAResetToken, error) {
	lg := d.lg.Derive(log.WithFunction("GetMFAResetToken"))

	if err := d.checkConnection(); err != nil {
		lg.Warnf("GetMFAResetToken: %v", err)
		return nil, err
	}

	var (
		token         model.MFAResetToken
		pendingSecret string
		keyID         sql.NullString
	)
	err := d.QueryRowContext(ctx, `
		SELECT user_id, token, pending_secret, pending_secret_key_id, valid_until, password_verified, attempts
		FROM mfa_reset_tokens
		WHERE user_id = $1
	`, userID).Scan(&token.UserId, &token.Token, &pendingSecret, &keyID, &token.ValidUntil,
		&token.PasswordVerified, &token.Attempts)
	if err != nil {
		if err == sql.ErrNoRows {
			lg.Debugf("no MFA reset token found for user: %s", userID)
			return nil, ErrNoMFAResetTokenFound
		}
		lg.Errorf("failed to retrieve MFA reset token: %v", err)
		return nil, err
	}

	token.PendingSecret, err = decryptSecret(pendingSecret, keyID.String, d.keyRing)
	if err != nil {
		lg.Errorf("GetMFAResetToken: %v", err)
		return nil, err
	}
	return &token, nil
}

// MarkMFAResetPasswordVerified flips the password_verified flag on a user's
// reset token, unlocking the QR/code-confirmation step. Called once the
// account password has been re-verified on the web confirmation page.
func (d *DB) MarkMFAResetPasswordVerified(ctx context.Context, userID string) error {
	lg := d.lg.Derive(log.WithFunction("MarkMFAResetPasswordVerified"))

	if err := d.checkConnection(); err != nil {
		lg.Warnf("MarkMFAResetPasswordVerified: %v", err)
		return err
	}

	_, err := d.ExecContext(ctx, `
		UPDATE mfa_reset_tokens SET password_verified = true
		WHERE user_id = $1
	`, userID)
	if err != nil {
		lg.Warnf("MarkMFAResetPasswordVerified: %v", err)
		return err
	}
	return nil
}

// IncrementMFAResetAttempts increments a reset token's failed-password
// counter and returns the new count, mirroring
// IncrementMFAChallengeAttempts's role for login MFA challenges. Returns
// ErrNoMFAResetTokenFound if the token no longer exists.
func (d *DB) IncrementMFAResetAttempts(ctx context.Context, userID string) (int, error) {
	lg := d.lg.Derive(log.WithFunction("IncrementMFAResetAttempts"))

	if err := d.checkConnection(); err != nil {
		lg.Warnf("IncrementMFAResetAttempts: %v", err)
		return 0, err
	}

	var attempts int
	err := d.QueryRowContext(ctx, `
		UPDATE mfa_reset_tokens SET attempts = attempts + 1
		WHERE user_id = $1
		RETURNING attempts
	`, userID).Scan(&attempts)
	if err != nil {
		if err == sql.ErrNoRows {
			lg.Debugf("no MFA reset token found for user: %s", userID)
			return 0, ErrNoMFAResetTokenFound
		}
		lg.Warnf("IncrementMFAResetAttempts: %v", err)
		return 0, err
	}
	return attempts, nil
}

// DeleteMFAResetToken removes a user's MFA reset token. Called after a
// successful (or superseded) reset.
func (d *DB) DeleteMFAResetToken(ctx context.Context, userID string) error {
	lg := d.lg.Derive(log.WithFunction("DeleteMFAResetToken"))

	if err := d.checkConnection(); err != nil {
		lg.Warnf("DeleteMFAResetToken: %v", err)
		return err
	}

	_, err := d.ExecContext(ctx, `
		DELETE FROM mfa_reset_tokens
		WHERE user_id = $1
	`, userID)
	return err
}

// cleanupMFAResetTokens removes all expired MFA reset tokens. Called by the
// database maintenance routine.
func (d *DB) cleanupMFAResetTokens(ctx context.Context) error {
	_, err := d.ExecContext(ctx, `
		DELETE FROM mfa_reset_tokens
		WHERE valid_until < now()
	`)
	return err
}
