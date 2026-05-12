package db

import (
	"embed"
	"fmt"

	migrate "github.com/rubenv/sql-migrate"
)

// Migrate applies all pending Up migrations from the provided embedded filesystem.
func (d *DB) Migrate(fs embed.FS) error {
	if err := d.checkConnection(); err != nil {
		return fmt.Errorf("migration: database not connected: %w", err)
	}

	source := migrate.EmbedFileSystemMigrationSource{
		FileSystem: fs,
		Root:       ".",
	}

	n, err := migrate.Exec(d.DB, "postgres", source, migrate.Up)
	if err != nil {
		return fmt.Errorf("migration failed: %w", err)
	}

	d.lg.Infof("applied %d migration(s)", n)
	return nil
}
