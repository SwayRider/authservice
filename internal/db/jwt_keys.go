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
	"time"

	"github.com/swayrider/swlib/crypto"

	log "github.com/swayrider/swlib/logger"
)

const (
	jwtRotateThresshold = 3 // Rotate 3 days before expiration
)

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

	var key string
	err := d.QueryRowContext(ctx, `
		SELECT private_key FROM jwt_keys
		WHERE valid_until > now()
		ORDER BY id DESC
		LIMIT 1`).Scan(&key)
	if err != nil {
		lg.Warnf("failed to retrieve key: %v", err)
		return "", err
	}
	return key, nil
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
	defer rows.Close()

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
	defer d.releaseLock(ctx, lockJwtRotation)

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

	_, err = d.ExecContext(ctx, `
		INSERT INTO jwt_keys (private_key, public_key, valid_until)
		VALUES ($1, $2, $3)
	`, privPEM, pubPEM, validUntil)
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
	return validUntil.Before(time.Now().Add(time.Hour * 24 * jwtRotateThresshold)), nil
}
