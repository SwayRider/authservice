// password_history.go implements storage of recent per-user password hashes.
//
// The last PasswordHistorySize hashes a user has set are kept so password
// change and reset flows can reject reuse of a recent password. Hashes are
// stored in the same Argon2id format as users.password_hash, so reuse checks
// reuse crypto.VerifyPassword.

package db

import (
	"context"

	"github.com/swayrider/swlib/crypto"
	log "github.com/swayrider/swlib/logger"
)

// AddToPasswordHistory records a newly-set password hash for userID and trims
// the user's history down to the configured size (newest N by created_at, id).
// Callers pass the already-hashed password. Failures are expected to be logged
// and ignored by the caller: history is a hardening feature, not a core-path
// dependency.
func (d *DB) AddToPasswordHistory(ctx context.Context, userID, passwordHash string) error {
	lg := d.lg.Derive(log.WithFunction("AddToPasswordHistory"))

	if err := d.checkConnection(); err != nil {
		lg.Warnf("AddToPasswordHistory: %v", err)
		return err
	}

	if _, err := d.ExecContext(ctx, `
		INSERT INTO password_history (user_id, password_hash)
		VALUES ($1, $2)
	`, userID, passwordHash); err != nil {
		lg.Warnf("failed to insert password history row: %v", err)
		return err
	}

	if _, err := d.ExecContext(ctx, `
		DELETE FROM password_history
		WHERE user_id = $1
		  AND id NOT IN (
		      SELECT id FROM password_history
		      WHERE user_id = $1
		      ORDER BY created_at DESC, id DESC
		      LIMIT $2
		  )
	`, userID, d.passwordHistorySize); err != nil {
		lg.Warnf("failed to trim password history: %v", err)
		return err
	}
	return nil
}

// CheckPasswordReuse reports whether newPassword matches any of the user's
// stored history hashes (up to the configured size). Used by password change
// and reset to reject rotating back to a recent password. A hash that cannot
// be verified (corrupt row) is treated as non-matching.
func (d *DB) CheckPasswordReuse(ctx context.Context, userID, newPassword string) (bool, error) {
	lg := d.lg.Derive(log.WithFunction("CheckPasswordReuse"))

	if err := d.checkConnection(); err != nil {
		lg.Warnf("CheckPasswordReuse: %v", err)
		return false, err
	}

	rows, err := d.QueryContext(ctx, `
		SELECT password_hash FROM password_history
		WHERE user_id = $1
		ORDER BY created_at DESC, id DESC
		LIMIT $2
	`, userID, d.passwordHistorySize)
	if err != nil {
		lg.Warnf("failed to query password history: %v", err)
		return false, err
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var hash string
		if err := rows.Scan(&hash); err != nil {
			lg.Warnf("failed to scan password history row: %v", err)
			return false, err
		}
		matches, err := crypto.VerifyPassword(hash, newPassword)
		if err != nil {
			lg.Warnf("failed to verify against history hash: %v", err)
			continue
		}
		if matches {
			return true, nil
		}
	}
	if err := rows.Err(); err != nil {
		lg.Warnf("failed to iterate password history: %v", err)
		return false, err
	}
	return false, nil
}

// cleanupPasswordHistory removes every user's history rows beyond the
// configured size. Run by the hourly maintenance routine as a safety net for
// rows written before the size was lowered.
func (d *DB) cleanupPasswordHistory(ctx context.Context) error {
	_, err := d.ExecContext(ctx, `
		DELETE FROM password_history
		WHERE id NOT IN (
		    SELECT id FROM (
		        SELECT id, ROW_NUMBER() OVER (
		            PARTITION BY user_id ORDER BY created_at DESC, id DESC
		        ) AS rn
		        FROM password_history
		    ) ranked
		    WHERE rn <= $1
		)
	`, d.passwordHistorySize)
	return err
}
