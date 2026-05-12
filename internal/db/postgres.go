// Package db provides PostgreSQL database access for the authservice.
//
// This package implements the data access layer for:
//   - User management (registration, lookup, verification)
//   - Token management (refresh, verification, password reset)
//   - JWT key storage and rotation
//   - Service client credentials
//
// All database operations include automatic connection checking and reconnection.
// The package uses advisory locks for coordinating operations across multiple
// service instances (e.g., JWT key rotation, database maintenance).
package db

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"

	log "github.com/swayrider/swlib/logger"
	//"github.com/swayrider/swlib/svcreg"

	_ "github.com/lib/pq"
)

// Config holds the PostgreSQL connection configuration.
type Config struct {
	Host     string // Database server hostname
	Port     int    // Database server port
	User     string // Database username
	Password string // Database password
	DBName   string // Database name
	SSLMode  string // SSL mode (disable, require, verify-ca, verify-full)
}

// DB wraps a PostgreSQL connection with automatic reconnection support.
// It embeds *sql.DB for direct access to standard database/sql methods.
type DB struct {
	*sql.DB
	cfg            *Config
	//resolver       *svcreg.Resolver
	//consulExternal bool
	mux            *sync.Mutex
	lg             *log.Logger
}

// New returns a new DB
//
// Parameters:
//   - cfg: the database configuration
//
// Returns:
//   - *DB: the database connection
//   - error: if the database connection could not be established
func New(
	cfg Config,
	//resolver *svcreg.Resolver,
	//consulExternal bool,
	l *log.Logger,
) (*DB, error) {
	lg := l.Derive(
		log.WithComponent("postgres"),
		log.WithFunction("New"),
	)

	d := &DB{
		cfg:            &cfg,
		//resolver:       resolver,
		//consulExternal: consulExternal,
		mux:            &sync.Mutex{},
		lg:             lg,
	}

	err := d.newConnection()
	if err != nil {
		return nil, err
	}

	return d, nil
}

// SqlDB returns the underlying *sql.DB connection.
// This implements the app.DB interface.
func (d DB) SqlDB() *sql.DB {
	return d.DB
}

// checkConnection verifies the database connection is alive and reconnects if needed.
// This method is thread-safe and should be called before any database operation.
func (d *DB) checkConnection() error {
	d.mux.Lock()
	defer d.mux.Unlock()

	if d.DB == nil {
		return d.newConnection()
	}
	if err := d.Ping(); err != nil {
		return d.newConnection()
	}
	return nil
}

// EnsureDatabase creates the target database if it does not already exist.
// It connects to the PostgreSQL server via the "postgres" maintenance database,
// then creates the configured database if absent.
func EnsureDatabase(cfg Config, l *log.Logger) error {
	lg := l.Derive(
		log.WithComponent("postgres"),
		log.WithFunction("EnsureDatabase"),
	)

	sslmode := cfg.SSLMode
	if sslmode == "" {
		sslmode = "disable"
	}

	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=postgres sslmode=%s",
		cfg.Host, cfg.Port, cfg.User, cfg.Password, sslmode)

	conn, err := sql.Open("postgres", dsn)
	if err != nil {
		return fmt.Errorf("failed to open postgres connection: %w", err)
	}
	defer conn.Close()

	if err := conn.Ping(); err != nil {
		return fmt.Errorf("failed to ping postgres: %w", err)
	}

	var exists bool
	if err := conn.QueryRow(
		"SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = $1)", cfg.DBName,
	).Scan(&exists); err != nil {
		return fmt.Errorf("failed to check database existence: %w", err)
	}

	if !exists {
		lg.Infof("creating database %q", cfg.DBName)
		// CREATE DATABASE cannot run inside a transaction.
		ident := `"` + strings.ReplaceAll(cfg.DBName, `"`, `""`) + `"`
		if _, err := conn.Exec("CREATE DATABASE " + ident); err != nil {
			return fmt.Errorf("failed to create database %q: %w", cfg.DBName, err)
		}
	}

	return nil
}

// newConnection establishes a new PostgreSQL connection using the stored configuration.
func (d *DB) newConnection() error {
	var host, user, password, dbname, sslmode string
	var port int

	password = d.cfg.Password

	// If config is set, we do not use the resolver !
	if d.cfg.Host != "" && d.cfg.Port != 0 && d.cfg.User != "" && d.cfg.DBName != "" {
		d.lg.Debugln("using database configuration from config file")

		host = d.cfg.Host
		port = d.cfg.Port
		user = d.cfg.User
		dbname = d.cfg.DBName
		sslmode = d.cfg.SSLMode
		if sslmode == "" {
			sslmode = "disable"
		}
	/*} else if d.resolver != nil {
		d.lg.Debugln("using database configuration from consul")

		serviceDesc, err := d.resolver.Get(svcreg.NewServiceQuery(
			"postgres", "database", "auth",
		))
		if err != nil {
			return err
		}

		host = serviceDesc.ServiceHost(d.consulExternal)
		port = serviceDesc.ServicePort(d.consulExternal)
		user = serviceDesc.MetaData["user"]
		dbname = serviceDesc.MetaData["db_name"]
		sslmode = serviceDesc.MetaData["ssl_mode"]*/
	} else {
		err := errors.New("no database configuration found")
		return err
	}

	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		host, port, user, password, dbname, sslmode)
	conn, err := sql.Open("postgres", dsn)
	if err != nil {
		d.lg.Errorf("failed to connect to database: %v", err)
		return err
	}
	if err := conn.Ping(); err != nil {
		return err
	}
	d.DB = conn
	return nil
}
