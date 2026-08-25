// mfa.go implements TOTP second-factor persistence: the per-user MFA
// enrollment (with the secret encrypted at rest), single-use backup codes,
// and pending-login challenge tokens.
//
// Encryption mirrors jwt_keys.go: user_mfa.secret holds an AES-256-GCM blob
// (base64) produced by the shared KeyRing, with the key fingerprint stored
// in secret_key_id so ENCRYPTION_MASTER_KEY_PREVIOUS-based rotation keeps
// working. A nil ring means the secret is stored as plaintext -- a
// defensive fallback / test seam, never used in production (dbCtor fails
// fast on a missing ENCRYPTION_MASTER_KEY).

package db

import (
	"context"
	"database/sql"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/swayrider/authservice/internal/model"
	"github.com/swayrider/swlib/crypto"
	"github.com/swayrider/swlib/encryption"
	log "github.com/swayrider/swlib/logger"
)

// MFAUser is the decrypted state of a user's user_mfa row.
type MFAUser struct {
	UserID  string
	Enabled bool
	Secret  string // plaintext; only ever returned during SetupMFA
}

// encryptSecret prepares a plaintext TOTP secret for the user_mfa.secret
// column. With a ring set the secret is encrypted under the ring's current
// key and base64-encoded, and the key fingerprint is returned for the
// secret_key_id column; with a nil ring it is stored as plaintext.
func encryptSecret(secret string, ring *encryption.KeyRing) (value, keyID string, err error) {
	if ring == nil {
		return secret, "", nil
	}

	blob, id, err := ring.EncryptCurrent([]byte(secret))
	if err != nil {
		return "", "", fmt.Errorf("failed to encrypt MFA secret: %w", err)
	}
	return base64.StdEncoding.EncodeToString(blob), id, nil
}

// decryptSecret reverses encryptSecret given a row's stored value and its
// secret_key_id. Plaintext rows (nil ring) are returned verbatim.
func decryptSecret(value, keyID string, ring *encryption.KeyRing) (string, error) {
	if ring == nil {
		return value, nil
	}

	blob, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return "", fmt.Errorf("failed to decode stored MFA secret: %w", err)
	}

	plain, err := ring.Decrypt(blob, keyID)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt MFA secret (key id %q): %w", keyID, err)
	}
	return string(plain), nil
}

// CreateMFASecret upserts the user's MFA enrollment with a new TOTP secret.
// The secret is encrypted through d.keyRing before storage (see
// encryptSecret). Re-setup replaces the previous secret and marks the row
// not-enabled, so the new secret must be verified and re-enabled before it
// takes effect. Backup codes are replaced by the caller via
// StoreBackupCodeHashes.
func (d *DB) CreateMFASecret(ctx context.Context, userID, secret string) error {
	lg := d.lg.Derive(log.WithFunction("CreateMFASecret"))

	if err := d.checkConnection(); err != nil {
		lg.Warnf("CreateMFASecret: %v", err)
		return err
	}

	storedSecret, keyID, err := encryptSecret(secret, d.keyRing)
	if err != nil {
		lg.Errorf("CreateMFASecret: %v", err)
		return err
	}

	_, err = d.ExecContext(ctx, `
		INSERT INTO user_mfa (user_id, enabled, secret, secret_key_id)
		VALUES ($1, false, $2, $3)
		ON CONFLICT (user_id) DO UPDATE
		SET enabled = false,
		    secret = EXCLUDED.secret,
		    secret_key_id = EXCLUDED.secret_key_id,
		    updated_at = now()
	`, userID, storedSecret, sql.NullString{String: keyID, Valid: keyID != ""})
	if err != nil {
		lg.Warnf("CreateMFASecret: %v", err)
		return err
	}
	return nil
}

// GetMFASecret returns the user's MFA enrollment with the secret decrypted.
// Returns ErrNoMFARecord when the user has no enrollment row.
func (d *DB) GetMFASecret(ctx context.Context, userID string) (*MFAUser, error) {
	lg := d.lg.Derive(log.WithFunction("GetMFASecret"))

	if err := d.checkConnection(); err != nil {
		lg.Warnf("GetMFASecret: %v", err)
		return nil, err
	}

	var (
		row    MFAUser
		secret string
		keyID  sql.NullString
	)
	err := d.QueryRowContext(ctx, `
		SELECT user_id, enabled, secret, secret_key_id FROM user_mfa
		WHERE user_id = $1
	`, userID).Scan(&row.UserID, &row.Enabled, &secret, &keyID)
	if err != nil {
		if err == sql.ErrNoRows {
			lg.Debugf("no MFA record found for user: %s", userID)
			return nil, ErrNoMFARecord
		}
		lg.Warnf("GetMFASecret: %v", err)
		return nil, err
	}

	row.Secret, err = decryptSecret(secret, keyID.String, d.keyRing)
	if err != nil {
		lg.Errorf("GetMFASecret: %v", err)
		return nil, err
	}
	return &row, nil
}

// ReplaceMFASecret swaps in a new TOTP secret for a user who already has an
// enabled enrollment, leaving enabled untouched (unlike CreateMFASecret,
// which always resets enabled to false). Used by the email-verified MFA
// reset flow (internal/web/reset_mfa.go), where the old secret must stay
// valid right up until the new one is confirmed -- there is no window where
// the account has no working second factor.
func (d *DB) ReplaceMFASecret(ctx context.Context, userID, secret string) error {
	lg := d.lg.Derive(log.WithFunction("ReplaceMFASecret"))

	if err := d.checkConnection(); err != nil {
		lg.Warnf("ReplaceMFASecret: %v", err)
		return err
	}

	storedSecret, keyID, err := encryptSecret(secret, d.keyRing)
	if err != nil {
		lg.Errorf("ReplaceMFASecret: %v", err)
		return err
	}

	_, err = d.ExecContext(ctx, `
		UPDATE user_mfa
		SET secret = $2, secret_key_id = $3, updated_at = now()
		WHERE user_id = $1
	`, userID, storedSecret, sql.NullString{String: keyID, Valid: keyID != ""})
	if err != nil {
		lg.Warnf("ReplaceMFASecret: %v", err)
		return err
	}
	return nil
}

// GetMFAStatus reports whether the user's MFA is enabled. A user with no
// enrollment row reports false (no error).
func (d *DB) GetMFAStatus(ctx context.Context, userID string) (bool, error) {
	lg := d.lg.Derive(log.WithFunction("GetMFAStatus"))

	if err := d.checkConnection(); err != nil {
		lg.Warnf("GetMFAStatus: %v", err)
		return false, err
	}

	var enabled bool
	err := d.QueryRowContext(ctx, `
		SELECT enabled FROM user_mfa
		WHERE user_id = $1
	`, userID).Scan(&enabled)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		lg.Warnf("GetMFAStatus: %v", err)
		return false, err
	}
	return enabled, nil
}

// EnableMFA marks the user's enrollment as enabled (after the new secret
// has been verified with a valid TOTP code).
func (d *DB) EnableMFA(ctx context.Context, userID string) error {
	lg := d.lg.Derive(log.WithFunction("EnableMFA"))

	if err := d.checkConnection(); err != nil {
		lg.Warnf("EnableMFA: %v", err)
		return err
	}

	_, err := d.ExecContext(ctx, `
		UPDATE user_mfa SET enabled = true, updated_at = now()
		WHERE user_id = $1
	`, userID)
	if err != nil {
		lg.Warnf("EnableMFA: %v", err)
		return err
	}
	return nil
}

// DisableMFA removes the user's enrollment and all of their backup codes.
func (d *DB) DisableMFA(ctx context.Context, userID string) error {
	lg := d.lg.Derive(log.WithFunction("DisableMFA"))

	if err := d.checkConnection(); err != nil {
		lg.Warnf("DisableMFA: %v", err)
		return err
	}

	if _, err := d.ExecContext(ctx, `
		DELETE FROM mfa_backup_codes WHERE user_id = $1
	`, userID); err != nil {
		lg.Warnf("DisableMFA: %v", err)
		return err
	}

	if _, err := d.ExecContext(ctx, `
		DELETE FROM user_mfa WHERE user_id = $1
	`, userID); err != nil {
		lg.Warnf("DisableMFA: %v", err)
		return err
	}
	return nil
}

// StoreBackupCodeHashes replaces all of the user's backup codes with the
// given hashes (delete + insert), so regenerating codes invalidates the
// previous set.
func (d *DB) StoreBackupCodeHashes(ctx context.Context, userID string, hashes []string) error {
	lg := d.lg.Derive(log.WithFunction("StoreBackupCodeHashes"))

	if err := d.checkConnection(); err != nil {
		lg.Warnf("StoreBackupCodeHashes: %v", err)
		return err
	}

	if _, err := d.ExecContext(ctx, `
		DELETE FROM mfa_backup_codes WHERE user_id = $1
	`, userID); err != nil {
		lg.Warnf("StoreBackupCodeHashes: %v", err)
		return err
	}

	for _, hash := range hashes {
		if _, err := d.ExecContext(ctx, `
			INSERT INTO mfa_backup_codes (user_id, code_hash)
			VALUES ($1, $2)
		`, userID, hash); err != nil {
			lg.Warnf("StoreBackupCodeHashes: %v", err)
			return err
		}
	}
	return nil
}

// ConsumeBackupCode atomically claims one of the user's unused backup
// codes for the presented plaintext code.
//
// The code is verified against the stored Argon2id hashes -- a direct hash
// lookup is impossible because every hash is salted (two hashes of the same
// code never compare equal), so verification must run the KDF against each
// unused row. The matching row is then claimed with a conditional UPDATE
// (WHERE used = false), so a code presented concurrently by two requests is
// used exactly once. This mirrors ConsumeRefreshToken, where the plaintext
// secret crosses into this layer and all crypto happens here.
//
// Reports whether a code was claimed; a wrong, already-used, or foreign
// code reports false.
func (d *DB) ConsumeBackupCode(ctx context.Context, userID, code string) (bool, error) {
	lg := d.lg.Derive(log.WithFunction("ConsumeBackupCode"))

	if err := d.checkConnection(); err != nil {
		lg.Warnf("ConsumeBackupCode: %v", err)
		return false, err
	}

	rows, err := d.QueryContext(ctx, `
		SELECT code_hash FROM mfa_backup_codes
		WHERE user_id = $1 AND used = false
	`, userID)
	if err != nil {
		lg.Warnf("ConsumeBackupCode: %v", err)
		return false, err
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var codeHash string
		if err := rows.Scan(&codeHash); err != nil {
			lg.Warnf("ConsumeBackupCode: %v", err)
			return false, err
		}

		ok, err := crypto.VerifyPassword(codeHash, code)
		if err != nil {
			// Malformed/undecodable hash -- skip and try the rest.
			lg.Debugf("ConsumeBackupCode: unverifiable hash: %v", err)
			continue
		}
		if !ok {
			continue
		}

		// Atomic claim: only an unused row can be claimed. If a concurrent
		// request already took it, try the remaining hashes (a code can only
		// match one, so this terminates quickly).
		var id int64
		err = d.QueryRowContext(ctx, `
			UPDATE mfa_backup_codes
			SET used = true, used_at = now()
			WHERE user_id = $1 AND code_hash = $2 AND used = false
			RETURNING id
		`, userID, codeHash).Scan(&id)
		if err == sql.ErrNoRows {
			continue
		}
		if err != nil {
			lg.Warnf("ConsumeBackupCode: %v", err)
			return false, err
		}
		return true, nil
	}
	if err := rows.Err(); err != nil {
		lg.Warnf("ConsumeBackupCode: %v", err)
		return false, err
	}
	return false, nil
}

// CreateMFAChallenge deletes any prior challenge for the user, then inserts
// a new pending-login challenge keyed by the SHA-256 hash of the raw token.
// Only the hash is ever stored.
func (d *DB) CreateMFAChallenge(ctx context.Context, userID, tokenHash string, validUntil time.Time) error {
	lg := d.lg.Derive(log.WithFunction("CreateMFAChallenge"))

	if err := d.checkConnection(); err != nil {
		lg.Warnf("CreateMFAChallenge: %v", err)
		return err
	}

	if _, err := d.ExecContext(ctx, `
		DELETE FROM mfa_challenges WHERE user_id = $1
	`, userID); err != nil {
		lg.Warnf("CreateMFAChallenge: %v", err)
		return err
	}

	if _, err := d.ExecContext(ctx, `
		INSERT INTO mfa_challenges (user_id, token_hash, valid_until)
		VALUES ($1, $2, $3)
	`, userID, tokenHash, validUntil); err != nil {
		lg.Warnf("CreateMFAChallenge: %v", err)
		return err
	}
	return nil
}

// GetMFAChallenge returns the challenge with the given token hash.
// Returns ErrNoMFAChallengeFound when no such challenge exists.
func (d *DB) GetMFAChallenge(ctx context.Context, tokenHash string) (*model.MFAChallenge, error) {
	lg := d.lg.Derive(log.WithFunction("GetMFAChallenge"))

	if err := d.checkConnection(); err != nil {
		lg.Warnf("GetMFAChallenge: %v", err)
		return nil, err
	}

	var challenge model.MFAChallenge
	err := d.QueryRowContext(ctx, `
		SELECT user_id, token_hash, attempts, valid_until FROM mfa_challenges
		WHERE token_hash = $1
	`, tokenHash).Scan(&challenge.UserID, &challenge.TokenHash, &challenge.Attempts, &challenge.ValidUntil)
	if err != nil {
		if err == sql.ErrNoRows {
			lg.Debugf("no MFA challenge found")
			return nil, ErrNoMFAChallengeFound
		}
		lg.Warnf("GetMFAChallenge: %v", err)
		return nil, err
	}
	return &challenge, nil
}

// IncrementMFAChallengeAttempts increments the challenge's guess counter
// and returns the new count. Returns ErrNoMFAChallengeFound when the
// challenge no longer exists.
func (d *DB) IncrementMFAChallengeAttempts(ctx context.Context, tokenHash string) (int, error) {
	lg := d.lg.Derive(log.WithFunction("IncrementMFAChallengeAttempts"))

	if err := d.checkConnection(); err != nil {
		lg.Warnf("IncrementMFAChallengeAttempts: %v", err)
		return 0, err
	}

	var attempts int
	err := d.QueryRowContext(ctx, `
		UPDATE mfa_challenges SET attempts = attempts + 1
		WHERE token_hash = $1
		RETURNING attempts
	`, tokenHash).Scan(&attempts)
	if err != nil {
		if err == sql.ErrNoRows {
			lg.Debugf("no MFA challenge found")
			return 0, ErrNoMFAChallengeFound
		}
		lg.Warnf("IncrementMFAChallengeAttempts: %v", err)
		return 0, err
	}
	return attempts, nil
}

// ConsumeMFAChallenge deletes the challenge, completing (or invalidating)
// the pending-login flow. Single-use by construction: the row is gone.
func (d *DB) ConsumeMFAChallenge(ctx context.Context, tokenHash string) error {
	lg := d.lg.Derive(log.WithFunction("ConsumeMFAChallenge"))

	if err := d.checkConnection(); err != nil {
		lg.Warnf("ConsumeMFAChallenge: %v", err)
		return err
	}

	if _, err := d.ExecContext(ctx, `
		DELETE FROM mfa_challenges WHERE token_hash = $1
	`, tokenHash); err != nil {
		lg.Warnf("ConsumeMFAChallenge: %v", err)
		return err
	}
	return nil
}

// cleanupMFAChallenges deletes expired pending-login challenges. Called by
// the hourly database maintenance routine.
func (d *DB) cleanupMFAChallenges(ctx context.Context) error {
	_, err := d.ExecContext(ctx, `
		DELETE FROM mfa_challenges
		WHERE valid_until < now()
	`)
	return err
}
