// jwt_keys.go implements JWT signing key management with automatic rotation.
//
// The authservice uses RSA key pairs for signing JWTs. Keys are stored in the
// database and automatically rotated before expiration. During rotation, both
// old and new keys remain valid to allow for seamless token verification.
//
// Key rotation is coordinated across multiple service instances using PostgreSQL
// advisory locks to prevent race conditions.

package db

import (
	"context"
	"database/sql"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/swayrider/swlib/crypto"
	"github.com/swayrider/swlib/encryption"

	log "github.com/swayrider/swlib/logger"
)

const (
	jwtRotateThreshold = 3 // Rotate 3 days before expiration
)

// encodeForStorage prepares a PEM private key for the private_key column.
// If ring is set, it is encrypted under the ring's current key and
// base64-encoded; otherwise it is stored as plaintext PEM (ring is always
// set in production since dbCtor fails fast on a missing/invalid
// ENCRYPTION_MASTER_KEY -- the nil branch exists only as a defensive
// fallback / test seam).
func encodeForStorage(privPEM string, ring *encryption.KeyRing) (value string, encrypted bool, keyID string, err error) {
	if ring == nil {
		return privPEM, false, "", nil
	}

	blob, id, err := ring.EncryptCurrent([]byte(privPEM))
	if err != nil {
		return "", false, "", fmt.Errorf("failed to encrypt private key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(blob), true, id, nil
}

// decodeFromStorage reverses encodeForStorage given a row's stored value
// and its private_key_encrypted flag. Plaintext rows (isEncrypted == false)
// are returned verbatim regardless of ring, preserving pre-encryption rows
// as readable without any backfill.
func decodeFromStorage(value string, isEncrypted bool, keyID string, ring *encryption.KeyRing) (string, error) {
	if !isEncrypted {
		return value, nil
	}
	if ring == nil {
		return "", fmt.Errorf("private key is encrypted but no encryption key ring is configured")
	}

	blob, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return "", fmt.Errorf("failed to decode stored private key: %w", err)
	}

	privPEM, err := ring.Decrypt(blob, keyID)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt private key (key id %q): %w", keyID, err)
	}
	return string(privPEM), nil
}

// EnsureKeys creates a new key pair if needed
func (d *DB) EnsureKeys(ctx context.Context) error {
	lg := d.lg.Derive(log.WithFunction("EnsureKeys"))

	if err := d.checkConnection(); err != nil {
		lg.Errorf("failed to check connection: %v", err)
		return err
	}

	needRotation, err := d.keysNeedRotation(ctx)
	if err != nil {
		lg.Errorf("failed to check keys: %v", err)
		return err
	}
	if !needRotation {
		return nil
	}

	return d.createNewKeyPair(ctx)
}

// GetSigningKey returns the current signing key
func (d *DB) GetSigningKey(ctx context.Context) (string, error) {
	lg := d.lg.Derive(log.WithFunction("GetSigningKey"))

	if err := d.checkConnection(); err != nil {
		lg.Errorf("failed to check connection: %v", err)
		return "", err
	}

	var (
		key       string
		encrypted bool
		keyID     sql.NullString
	)
	err := d.QueryRowContext(ctx, `
		SELECT private_key, private_key_encrypted, encryption_key_id FROM jwt_keys
		WHERE valid_until > now()
		ORDER BY id DESC
		LIMIT 1`).Scan(&key, &encrypted, &keyID)
	if err != nil {
		lg.Warnf("failed to retrieve key: %v", err)
		return "", err
	}

	privPEM, err := decodeFromStorage(key, encrypted, keyID.String, d.keyRing)
	if err != nil {
		lg.Errorf("failed to decode signing key (key id %q): %v", keyID.String, err)
		return "", err
	}
	return privPEM, nil
}

// GetVerificationKeys returns the current verification keys
//
// This function returns multiple key, because we might be in a transitional
// state here. Meaning that the old key can still be valid while the new key
// is already active.
func (d *DB) GetVerificationKeys(ctx context.Context) ([]string, error) {
	lg := d.lg.Derive(log.WithFunction("GetVerificationKeys"))

	if err := d.checkConnection(); err != nil {
		lg.Errorf("failed to check connection: %v", err)
		return nil, err
	}

	var keys []string
	rows, err := d.QueryContext(ctx, `
		SELECT public_key FROM jwt_keys
		WHERE valid_until > now()
		ORDER BY id DESC`)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var key string
		err = rows.Scan(&key)
		if err != nil {
			lg.Warnf("failed to retrieve keys: %v", err)
			return nil, err
		}
		keys = append(keys, key)
	}

	return keys, nil
}

// createNewKeyPair creates a new key pair
func (d *DB) createNewKeyPair(ctx context.Context) error {
	lg := d.lg.Derive(log.WithFunction("createNewKeyPair"))

	lockAcquired, err := d.acquireLockOrFail(ctx, lockJwtRotation)
	if err != nil {
		lg.Warnf("failed to acquire lock: %v", err)
		return err
	}
	if !lockAcquired {
		lg.Debugln("lock already acquired")
		return nil
	}
	defer func() { _ = d.releaseLock(ctx, lockJwtRotation) }()

	// Recheck if we need a rotation
	// We might have entered this function because a rotation is needed, but
	// at the same time another instance might have done the same and beat us
	// at the lock.
	needRotation, err := d.keysNeedRotation(ctx)
	if err != nil {
		return err
	}
	if !needRotation {
		return nil
	}

	privPEM, pubPEM, validUntil, err := crypto.CreateKeypair()
	if err != nil {
		lg.Warnf("failed to create keypair: %v", err)
		return err
	}

	storedKey, encrypted, keyID, err := encodeForStorage(privPEM, d.keyRing)
	if err != nil {
		lg.Warnf("failed to encode private key for storage: %v", err)
		return err
	}

	_, err = d.ExecContext(ctx, `
		INSERT INTO jwt_keys (private_key, public_key, valid_until, private_key_encrypted, encryption_key_id)
		VALUES ($1, $2, $3, $4, $5)
	`, storedKey, pubPEM, validUntil, encrypted, sql.NullString{String: keyID, Valid: keyID != ""})
	if err != nil {
		lg.Warnf("failed to insert keypair: %v", err)
		return err
	}

	return nil
}

// keysNeedRotation checks if a key rotation is needed
func (d *DB) keysNeedRotation(ctx context.Context) (bool, error) {
	lg := d.lg.Derive(log.WithFunction("keysNeedRotation"))

	var validUntil time.Time
	err := d.QueryRowContext(ctx, `
		SELECT valid_until FROM jwt_keys
		ORDER BY id DESC
		LIMIT 1`).Scan(&validUntil)
	if err != nil {
		if err == sql.ErrNoRows {
			return true, nil
		}
		lg.Warnf("failed to retrieve latest jwt_keys: %v", err)
		return false, err
	}
	return validUntil.Before(time.Now().Add(time.Hour * 24 * jwtRotateThreshold)), nil
}

// cleanupExpiredJwtKeys deletes jwt_keys rows that expired more than
// retentionDays ago. Expired rows are never read again (GetSigningKey and
// GetVerificationKeys both filter valid_until > now()); the retention
// window exists only as a forensics/clock-skew safety margin.
func (d *DB) cleanupExpiredJwtKeys(ctx context.Context, retentionDays int) error {
	_, err := d.ExecContext(ctx, `
		DELETE FROM jwt_keys
		WHERE valid_until < now() - make_interval(days => $1)
	`, retentionDays)
	return err
}
