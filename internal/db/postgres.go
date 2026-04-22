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
