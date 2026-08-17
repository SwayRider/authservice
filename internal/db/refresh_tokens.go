// refresh_tokens.go implements refresh token storage and management.
//
// Refresh tokens are used for the "remember me" functionality and allow users
// to obtain new access tokens without re-authenticating. Each token is bound to:
//   - The user who created it
//   - The JWT ID of the associated access token
//   - The client's IP address (gateway-resolved; a soft anomaly signal, never
//     a gate on refresh) and user agent
//
// Only one refresh token is allowed per user at a time. Creating a new token
// automatically invalidates any existing token for that user.

package db

import (
	"context"
	"database/sql"

	"github.com/swayrider/authservice/internal/model"
	log "github.com/swayrider/swlib/logger"
)

// CreateRefreshToken creates a new refresh token
func (d *DB) CreateRefreshToken(
	ctx context.Context,
	user *model.User,
	jwtID, ip, userAgent string,
) (token *model.RefreshToken, err error) {
	lg := d.lg.Derive(log.WithFunction("CreateRefreshToken"))

	err = d.DeleteRefreshTokensByUserID(ctx, user.ID)
	if err != nil {
		lg.Warnf("CreateRefreshToken: %v", err)
		return
	}

	token, err = model.NewRefreshToken(user, jwtID, model.DefaultRefreshTokenTTL, ip, userAgent)
	if err != nil {
		lg.Warnf("CreateRefreshToken: %v", err)
		return
	}

	_, err = d.ExecContext(ctx, `
		INSERT INTO refresh_tokens
		(token_hash, user_id, jwtid, valid_until, created_ip, user_agent)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, token.TokenHash, token.UserId, token.JwtID, token.ValidUntil, token.Ip, token.UserAgent)
	if err != nil {
		lg.Warnf("CreateRefreshToken: %v", err)
		return
	}

	return
}

// ConsumeRefreshToken atomically retrieves and deletes a refresh token in a
// single statement, so concurrent refreshes of the same token cannot both
// succeed (only one DELETE finds a row; the other gets ErrNoRefreshTokenFound).
// Returns ErrNoRefreshTokenFound if the token doesn't exist or was already consumed.
func (d *DB) ConsumeRefreshToken(
	ctx context.Context,
	token string,
) (*model.RefreshToken, error) {
	lg := d.lg.Derive(log.WithFunction("ConsumeRefreshToken"))

	if err := d.checkConnection(); err != nil {
		lg.Warnf("ConsumeRefreshToken: %v", err)
		return nil, err
	}

	hash := model.HashToken(token)
	var rt model.RefreshToken
	err := d.QueryRowContext(ctx, `
		DELETE FROM refresh_tokens
		WHERE token_hash = $1
		RETURNING user_id, jwtid, valid_until, revoked, created_ip, user_agent
	`, hash).Scan(&rt.UserId, &rt.JwtID, &rt.ValidUntil, &rt.Revoked, &rt.Ip, &rt.UserAgent)
	if err != nil {
		if err == sql.ErrNoRows {
			lg.Debugf("no refresh token found")
			return nil, ErrNoRefreshTokenFound
		}
		lg.Warnf("ConsumeRefreshToken: %v", err)
		return nil, err
	}
	return &rt, nil
}

// DeleteRefreshToken removes a refresh token from the database.
// This is called during logout to invalidate the user's session.
func (d *DB) DeleteRefreshToken(
	ctx context.Context,
	token string,
) error {
	lg := d.lg.Derive(log.WithFunction("DeleteRefreshToken"))

	if err := d.checkConnection(); err != nil {
		lg.Warnf("DeleteRefreshToken: %v", err)
		return err
	}

	hash := model.HashToken(token)
	_, err := d.ExecContext(ctx, `
		DELETE FROM refresh_tokens
		WHERE token_hash = $1
	`, hash)
	return err
}

// DeleteRefreshTokensByUserID removes all refresh tokens belonging to a user.
// This is used to revoke every active session for a user, e.g. when issuing
// a new token (only one refresh token is allowed per user) and after a
// password change/reset (to invalidate any tokens that may have been stolen).
func (d *DB) DeleteRefreshTokensByUserID(
	ctx context.Context,
	userID string,
) error {
	lg := d.lg.Derive(log.WithFunction("DeleteRefreshTokensByUserID"))

	if err := d.checkConnection(); err != nil {
		lg.Warnf("DeleteRefreshTokensByUserID: %v", err)
		return err
	}

	_, err := d.ExecContext(ctx, `
		DELETE FROM refresh_tokens
		WHERE user_id = $1
	`, userID)
	return err
}

// cleanupRefreshTokens deletes expired refresh tokens
func (d *DB) cleanupRefreshTokens(ctx context.Context) error {
	_, err := d.ExecContext(ctx, `
		DELETE FROM refresh_tokens
		WHERE valid_until < now() OR revoked = true
	`)
	return err
}
