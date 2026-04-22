// refresh_tokens.go implements refresh token storage and management.
//
// Refresh tokens are used for the "remember me" functionality and allow users
// to obtain new access tokens without re-authenticating. Each token is bound to:
//   - The user who created it
//   - The JWT ID of the associated access token
//   - The client's IP address and user agent (for security validation)
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

	err = d.DeleteRefreshToken(ctx, user.ID)
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
		(token, user_id, jwtid, valid_until, created_ip, user_agent)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, token.Token, token.UserId, token.JwtID, token.ValidUntil, token.Ip, token.UserAgent)
	if err != nil {
		lg.Warnf("CreateRefreshToken: %v", err)
		return
	}

	return
}

// GetRefreshToken retrieves a refresh token by its token value.
// Returns ErrNoRefreshTokenFound if the token doesn't exist.
func (d *DB) GetRefreshToken(
	ctx context.Context,
	token string,
) (*model.RefreshToken, error) {
	lg := d.lg.Derive(log.WithFunction("GetRefreshToken"))

	if err := d.checkConnection(); err != nil {
		lg.Warnf("GetRefreshToken: %v", err)
		return nil, err
	}

	var rt model.RefreshToken
	err := d.QueryRowContext(ctx, `
		SELECT token, user_id, jwtid, valid_until, created_ip, user_agent FROM refresh_tokens
		WHERE token = $1
	`, token).Scan(&rt.Token, &rt.UserId, &rt.JwtID, &rt.ValidUntil, &rt.Ip, &rt.UserAgent)
	if err != nil {
		if err == sql.ErrNoRows {
			lg.Debugf("no refresh token found: %s", token)
			return nil, ErrNoRefreshTokenFound
		}
		lg.Warnf("GetRefreshToken: %v", err)
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

	_, err := d.ExecContext(ctx, `
		DELETE FROM refresh_tokens
		WHERE token = $1
	`, token)
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
