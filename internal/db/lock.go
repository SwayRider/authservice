// lock.go implements distributed locking using PostgreSQL advisory locks.
//
// Advisory locks are used to coordinate operations across multiple service
// instances without blocking database access. They are used for:
//   - JWT key rotation (prevents duplicate key creation)
//   - Database maintenance (prevents concurrent cleanup operations)

package db

import "context"

// lockId identifies different advisory lock types.
type lockId int64

// Advisory lock identifiers.
const (
	lockJwtRotation   lockId = 1 // Lock for JWT key rotation
	LockDbMaintenance lockId = 2 // Lock for database maintenance tasks
)

// acquireLockOrFail tries to acquire a lock. If it fails, it returns the error
func (d *DB) acquireLockOrFail(ctx context.Context, id lockId) (bool, error) {
	var gotLock bool
	err := d.QueryRowContext(ctx, `SELECT pg_try_advisory_lock($1)`, id).Scan(&gotLock)
	return gotLock, err
}

// releaseLock releases a lock
//
// This should be defered right after acquiring the lock
func (d *DB) releaseLock(ctx context.Context, id lockId) error {
	_, err := d.ExecContext(ctx, `SELECT pg_advisory_unlock($1)`, id)
	return err
}
