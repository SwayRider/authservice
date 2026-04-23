// Package main implements the authservice binary.
//
// The authservice provides user authentication and authorization for the SwayRider platform.
// It exposes three interfaces:
//   - gRPC on port 8081 for internal service-to-service communication
//   - REST on port 8080 via grpc-gateway for HTTP API access
//   - Web on port 8000 for serving HTML pages (email verification completion)
//
// # Service Components
//
// The service initializes several components on startup:
//   - PostgreSQL database connection with automatic reconnection
//   - Mail service client for sending verification and password reset emails
//   - JWT key management with automatic key rotation
//   - Background maintenance routines for token cleanup
//
// # Bootstrap Process
//
// On first run, the service will:
//  1. Create an initial admin user (requires ADMIN_EMAIL and ADMIN_PASSWORD)
//  2. Generate the first RSA key pair for JWT signing
//
// # Background Routines
//
// Two background goroutines run continuously:
//   - keyChecker: Rotates JWT signing keys before expiration (hourly check)
//   - dbMaintenance: Cleans up expired tokens (hourly)
package main

import (
	"context"
	"time"
	"fmt"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"github.com/swayrider/grpcclients"
	"github.com/swayrider/grpcclients/mailclient"
	authv1 "github.com/swayrider/protos/auth/v1"
	healthv1 "github.com/swayrider/protos/health/v1"
	"github.com/swayrider/authservice/internal/db"
	"github.com/swayrider/authservice/internal/server"
	"github.com/swayrider/authservice/internal/web"
	log "github.com/swayrider/swlib/logger"

	"github.com/swayrider/swlib/app"
	"github.com/swayrider/swlib/crypto"
)

/*
Flags:
	-http-port				(default: 8080)
	-grpc-port				(default: 8081)
	-web-port				(default: 8000)
	-web-path-prefix		(default: /web)

	-db-host
	-db-port
	-db-name
	-db-user
	-db-password
	-db-ssl-mode			(Default: disable)

	-admin-email
	-admin-password
	-mailer-address			(default: swayrider@example.com)

	-mailservice-host
	-mailservice-port

Environment variables:
	HTTP_PORT
	GRPC_PORT
	WEB_PORT
	WEB_PATH_PREFIX

	DB_HOST
	DB_PORT
	DB_NAME
	DB_USER
	DB_PASSWORD
	DB_SSL_MODE

	ADMIN_EMAIL
	ADMIN_PASSWORD
	MAILER_ADDRESS

	MAILSERVICE_HOST
	MAILSERVICE_PORT
*/

const (
	FldAdminEmail    = "admin-email"
	FldAdminPassword = "admin-password"
	FldMailerAddress = "mailer-address"

	EnvAdminEmail    = "ADMIN_EMAIL"
	EnvAdminPassword = "ADMIN_PASSWORD"
	EnvMailerAddress = "MAILER_ADDRESS"

	DefAdminEmail    = ""
	DefAdminPassword = ""
	DefMailerAddress = "swayrider@example.com"
)

func main() {
	stdConfigFields :=
			app.BackendServiceFields |
			app.DatabaseConnectionFields |
			app.WebServiceFields

	application := app.New("authservice").
		WithDefaultConfigFields(stdConfigFields, app.FlagGroupOverrides{}).
		WithServiceClients(
			app.NewServiceClient("mailservice", mailServiceClientCtor),
		).
		WithConfigFields(
			app.NewStringConfigField(
				FldAdminEmail, EnvAdminEmail,
				"Administrator email", DefAdminEmail),
			app.NewStringConfigField(
				FldAdminPassword, EnvAdminPassword,
				"Administrator password", DefAdminPassword),
			app.NewStringConfigField(
				FldMailerAddress, EnvMailerAddress,
				"Address used to send emails from", DefMailerAddress),
		).
		WithDatabase(dbCtor, dbBootstrap).
		WithBackgroundRoutines(
			keyChecker,
			dbMaintenance,
		)

	grpcConfig := app.NewGrpcConfig(
		app.AuthInterceptor|app.ClientInfoInterceptor,
		func() ([]string, error) {
			return application.Database().(*db.DB).GetVerificationKeys(
				context.Background())
		},
		app.GrpcServiceHooks{
			ServiceRegistrar:   grpcAuthRegistrar,
			ServiceHTTPHandler: grpcAuthGateway(application),
		},
		app.GrpcServiceHooks{
			ServiceRegistrar:   grpcHealthRegistrar,
			ServiceHTTPHandler: grpcHealthGateway(application),
		},
	)
	grpcConfig.SetForwardResponseFn(server.CookieForwarder)
	grpcConfig.SetHeaderMatcherFn(server.CookieHeaderMatcher)
	application = application.WithGrpc(grpcConfig)
	application = application.WithHTTP(startWebServer, stopWebServer)
	application.Run()
}

// mailServiceClientCtor creates a new mail service gRPC client.
// This client is used to send verification and password reset emails.
func mailServiceClientCtor(a app.App) grpcclients.Client {
	lg := a.Logger().Derive(log.WithFunction("mailServiceClientCtor"))
	clnt, err := mailclient.New(
		app.ServiceClientHostAndPort(a, "mailservice"))
	if err != nil {
		lg.Fatalf("failed to create mailservice client: %v", err)
	}
	return clnt
}

// dbCtor creates and returns the PostgreSQL database connection.
// The connection is configured from environment variables or CLI flags.
func dbCtor(a app.App) app.DB {
	lg := a.Logger().Derive(log.WithFunction("dbCtor"))

	cfg := db.Config{
		Password: app.GetConfigField[string](a.Config(), app.KeyDBPassword),
		Host:     app.GetConfigField[string](a.Config(), app.KeyDBHost),
		Port:     app.GetConfigField[int](a.Config(), app.KeyDBPort),
		User:     app.GetConfigField[string](a.Config(), app.KeyDBUser),
		DBName:   app.GetConfigField[string](a.Config(), app.KeyDBName),
		SSLMode:  app.GetConfigField[string](a.Config(), app.KeyDBSSLMode),
	}

	conn, err := db.New(
		cfg,
		a.Logger())

	if err != nil {
		lg.Fatalf("failed to create database connection: %v", err)
	}
	return conn
}

// dbBootstrap initializes required database state on startup.
// This includes creating the initial admin user and ensuring JWT keys exist.
func dbBootstrap(a app.App) error {
	lg := a.Logger().Derive(log.WithFunction("dbBootstrap"))
	dbconn := a.Database().(*db.DB)
	cfg := a.Config()

	bootstrapAdmin(cfg, dbconn, lg)
	bootstrapKeys(dbconn, lg)
	return nil
}

// bootstrapAdmin creates the initial admin user if one doesn't exist.
// Requires ADMIN_EMAIL and ADMIN_PASSWORD to be set in the configuration.
func bootstrapAdmin(cfg *app.Config, dbconn *db.DB, l *log.Logger) {
	ctx := context.Background()

	adminExists, err := dbconn.AdminExists(ctx)
	if err != nil {
		l.Fatalf("failed to check if admin exists: %v", err)
	}

	adminEmail := app.GetConfigField[string](cfg, FldAdminEmail)
	adminPassword := app.GetConfigField[string](cfg, FldAdminPassword)

	if !adminExists {
		l.Infoln("configuring admin user")
		if adminEmail == "" || adminPassword == "" {
			l.Fatalln("admin email or password not set")
		}

		hashedPassword, err := crypto.CalculatePasswordHash(adminPassword)
		if err != nil {
			l.Fatalf("failed to calculate password hash: %v", err)
		}
		if _, err := dbconn.CreateAdminUser(
			ctx, adminEmail, hashedPassword,
		); err != nil {
			l.Fatalf("failed to create admin user: %v", err)
		}
	}
}

// bootstrapKeys ensures at least one valid JWT signing key pair exists.
func bootstrapKeys(dbconn *db.DB, l *log.Logger) {
	ctx := context.Background()

	if err := dbconn.EnsureKeys(ctx); err != nil {
		l.Fatalf("failed to ensure keys: %v", err)
	}
}

// keyChecker is a background routine that ensures JWT keys are rotated
// before expiration. It runs hourly and creates new keys 3 days before
// the current key expires, allowing for a smooth transition period.
func keyChecker(a app.App) {
	lg := a.Logger().Derive(log.WithFunction("keyChecker"))
	dbconn := a.Database().(*db.DB)
	ctx := a.BackgroundContext()
	defer func() {
		a.BackgroundWaitGroup().Done()
	}()

	ticker := time.NewTicker(1 * time.Hour)
	for {
		select {
		case <-ticker.C:
			if err := dbconn.EnsureKeys(ctx); err != nil {
				lg.Errorf("failed to ensure keys: %v", err)
			}
		case <-ctx.Done():
			lg.Infoln("stopping key checker")
			ticker.Stop()
			return
		}
	}
}

// dbMaintenance is a background routine that cleans up expired tokens.
// It runs hourly and removes expired refresh tokens, verification tokens,
// and password reset tokens from the database.
func dbMaintenance(a app.App) {
	lg := a.Logger().Derive(log.WithFunction("dbMaintenance"))
	dbconn := a.Database().(*db.DB)
	ctx := a.BackgroundContext()
	defer func() {
		a.BackgroundWaitGroup().Done()
	}()

	ticker := time.NewTicker(1 * time.Hour)
	for {
		select {
		case <-ticker.C:
			if err := dbconn.EnsureKeys(ctx); err != nil {
				lg.Errorf("failed to ensure keys: %v", err)
			}
		case <-ctx.Done():
			lg.Infoln("stopping db maintenance")
			ticker.Stop()
			return
		}
	}
}

// grpcAuthRegistrar registers the AuthService gRPC server with the registrar.
func grpcAuthRegistrar(r grpc.ServiceRegistrar, a app.App) {
	mailClient := app.GetServiceClient[*mailclient.Client](a, "mailservice")
	mailerAddress := app.GetConfigField[string](a.Config(), FldMailerAddress)
	srv := server.NewAuthServer(
		a.Database().(*db.DB),
		a.Logger(),
		mailClient,
		mailerAddress,
	)
	authv1.RegisterAuthServiceServer(r, srv)
}

// grpcHealthRegistrar registers the HealthService gRPC server with the registrar.
func grpcHealthRegistrar(r grpc.ServiceRegistrar, a app.App) {
	srv := server.NewHealthServer(a.Logger())
	healthv1.RegisterHealthServiceServer(r, srv)
}

// grpcAuthGateway returns an HTTP handler that proxies REST requests to gRPC.
func grpcAuthGateway(a app.App) app.ServiceHTTPHandler {
	return func(
		ctx context.Context,
		mux *runtime.ServeMux,
		endpoint string,
		opts []grpc.DialOption,
	) error {
		lg := a.Logger().Derive(log.WithFunction("AuthServiceHTTPHandler"))
		if err := authv1.RegisterAuthServiceHandlerFromEndpoint(
			ctx, mux, endpoint, opts,
		); err != nil {
			lg.Fatalf("failed to register auth gRPC gateway: %v", err)
		}
		return nil
	}
}

// grpcHealthGateway returns an HTTP handler that proxies health check requests to gRPC.
func grpcHealthGateway(a app.App) app.ServiceHTTPHandler {
	return func(
		ctx context.Context,
		mux *runtime.ServeMux,
		endpoint string,
		opts []grpc.DialOption,
	) error {
		lg := a.Logger().Derive(log.WithFunction("HealthServiceHTTPHandler"))
		if err := healthv1.RegisterHealthServiceHandlerFromEndpoint(
			ctx, mux, endpoint, opts,
		); err != nil {
			lg.Fatalf("failed to register health gRPC gateway: %v", err)
		}
		return nil
	}
}

// startWebServer starts the static web server for serving HTML pages.
// This is used for email verification completion pages.
func startWebServer(a app.App) error {
	lg := a.Logger().Derive(log.WithFunction("startWebServer"))
	port := app.GetConfigField[int](a.Config(), app.KeyWebPort)
	prefix := app.GetConfigField[string](a.Config(), app.KeyWebPathPrefix)
	ws := web.New(
		fmt.Sprintf("0.0.0.0:%d", port),
		prefix, a.Database().(*db.DB),
		a.Logger())
	if err := ws.Start(); err != nil {
		lg.Errorf("failed to start web server: %v", err)
		return err
	}
	a.SetStaticHttpServer(ws)
	lg.Infof("Static webserver running on port: %d", port)
	return nil
}

// stopWebServer gracefully shuts down the web server.
func stopWebServer(a app.App) {
	lg := a.Logger().Derive(log.WithFunction("stopWebServer"))
	lg.Infoln("stopping web server")
	ws, ok := a.GetStaticHttpServer().(*web.WebServer)
	if !ok {
		err := fmt.Errorf("expected web server, got %T", a.GetStaticHttpServer())
		lg.Fatalf("failed to stop web server: %v", err)
	}
	if err := ws.Shutdown(a.BackgroundContext()); err != nil {
		lg.Warnf("failed to stop web server: %v", err)
	}
}
