// maintenance.go implements periodic database cleanup tasks.
//
// The maintenance routine removes expired tokens to prevent unbounded database
// growth. It is coordinated across service instances using advisory locks.

package db

import (
	"context"

	log "github.com/swayrider/swlib/logger"
)

// DoDatabaseMaintenance does database maintenance tasks
func (d *DB) DoDatabaseMaintenance(ctx context.Context) error {
	lg := d.lg.Derive(log.WithFunction("DoDatabaseMaintenance"))

	if err := d.checkConnection(); err != nil {
		lg.Errorf("failed to check connection: %v", err)
		return err
	}

	lockAcquired, err := d.acquireLockOrFail(ctx, LockDbMaintenance)
	if err != nil {
		lg.Warnf("failed to acquire lock: %v", err)
		return err
	}
	if !lockAcquired {
		lg.Debugln("lock already acquired")
		return nil
	}
	defer d.releaseLock(ctx, LockDbMaintenance)

	err = d.cleanupRefreshTokens(ctx)
	if err != nil {
		lg.Warnf("failed to cleanup refresh tokens: %v", err)
		return err
	}

	err = d.cleanupVerificationTokens(ctx)
	if err != nil {
		lg.Warnf("failed to cleanup verification tokens: %v", err)
		return err
	}

	err = d.cleanupPasswordResetTokens(ctx)
	if err != nil {
		lg.Warnf("failed to cleanup password reset tokens: %v", err)
		return err
	}

	return nil
}
