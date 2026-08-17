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
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"github.com/swayrider/grpcclients"
	"github.com/swayrider/grpcclients/mailclient"
	authv1 "github.com/swayrider/protos/auth/v1"
	healthv1 "github.com/swayrider/protos/health/v1"
	"github.com/swayrider/authservice/internal/db"
	"github.com/swayrider/authservice/internal/server"
	"github.com/swayrider/authservice/internal/web"
	"github.com/swayrider/authservice/migrations"
	"github.com/swayrider/swlib/http/cookies"
	log "github.com/swayrider/swlib/logger"
	"github.com/swayrider/swlib/ratelimit"

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

	REGISTRATION_MODE
	REGISTRATION_URL

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

	FldRegistrationMode = "registration-mode"
	FldRegistrationUrl  = "registration-url"

	EnvRegistrationMode = "REGISTRATION_MODE"
	EnvRegistrationUrl  = "REGISTRATION_URL"

	DefRegistrationMode = "open"
	DefRegistrationUrl  = ""

	FldVerificationUrl  = "verification-url"
	FldResetPasswordUrl = "reset-password-url"

	EnvVerificationUrl  = "VERIFICATION_URL"
	EnvResetPasswordUrl = "RESET_PASSWORD_URL"

	DefVerificationUrl  = ""
	DefResetPasswordUrl = ""

	FldLoginLockoutThreshold     = "login-lockout-threshold"
	FldLoginLockoutWindowSecs    = "login-lockout-window-secs"
	FldLoginLockoutDurationSecs  = "login-lockout-duration-secs"
	FldClientLockoutThreshold    = "client-lockout-threshold"
	FldClientLockoutWindowSecs   = "client-lockout-window-secs"
	FldClientLockoutDurationSecs = "client-lockout-duration-secs"
	FldEmailCooldownSecs         = "email-cooldown-secs"

	EnvLoginLockoutThreshold     = "LOGIN_LOCKOUT_THRESHOLD"
	EnvLoginLockoutWindowSecs    = "LOGIN_LOCKOUT_WINDOW_SECS"
	EnvLoginLockoutDurationSecs  = "LOGIN_LOCKOUT_DURATION_SECS"
	EnvClientLockoutThreshold    = "CLIENT_LOCKOUT_THRESHOLD"
	EnvClientLockoutWindowSecs   = "CLIENT_LOCKOUT_WINDOW_SECS"
	EnvClientLockoutDurationSecs = "CLIENT_LOCKOUT_DURATION_SECS"
	EnvEmailCooldownSecs         = "EMAIL_COOLDOWN_SECS"

	DefLoginLockoutThreshold     = 5
	DefLoginLockoutWindowSecs    = 900
	DefLoginLockoutDurationSecs  = 900
	DefClientLockoutThreshold    = 5
	DefClientLockoutWindowSecs   = 900
	DefClientLockoutDurationSecs = 900
	DefEmailCooldownSecs         = 60

	FldRateLimitRPS         = "rate-limit-rps"
	FldRateLimitBurst       = "rate-limit-burst"
	FldRateLimitIdleTTLSecs = "rate-limit-idle-ttl-secs"

	EnvRateLimitRPS         = "RATE_LIMIT_RPS"
	EnvRateLimitBurst       = "RATE_LIMIT_BURST"
	EnvRateLimitIdleTTLSecs = "RATE_LIMIT_IDLE_TTL_SECS"

	DefRateLimitRPS         = 50
	DefRateLimitBurst       = 100
	DefRateLimitIdleTTLSecs = 300
)

func main() {
	if ns := os.Getenv("COOKIE_NAMESPACE"); ns != "" {
		cookies.SetNamespace(ns)
	}

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
			app.NewStringConfigField(
				FldRegistrationMode, EnvRegistrationMode,
				"Registration mode (open or invite_only)", DefRegistrationMode),
			app.NewStringConfigField(
				FldRegistrationUrl, EnvRegistrationUrl,
				"URL of the registration page (used in invite emails)", DefRegistrationUrl),
			app.NewStringConfigField(
				FldVerificationUrl, EnvVerificationUrl,
				"Default URL for email verification (used when caller omits verificationUrl)", DefVerificationUrl),
			app.NewStringConfigField(
				FldResetPasswordUrl, EnvResetPasswordUrl,
				"Default URL for password reset (used when caller omits resetUrl)", DefResetPasswordUrl),
			app.NewIntConfigField(
				FldLoginLockoutThreshold, EnvLoginLockoutThreshold,
				"Failed Login attempts before an account is locked out", DefLoginLockoutThreshold),
			app.NewIntConfigField(
				FldLoginLockoutWindowSecs, EnvLoginLockoutWindowSecs,
				"Sliding window (seconds) over which failed Login attempts are counted", DefLoginLockoutWindowSecs),
			app.NewIntConfigField(
				FldLoginLockoutDurationSecs, EnvLoginLockoutDurationSecs,
				"Lockout duration (seconds) once the Login failure threshold is reached", DefLoginLockoutDurationSecs),
			app.NewIntConfigField(
				FldClientLockoutThreshold, EnvClientLockoutThreshold,
				"Failed GetToken attempts before a service client is locked out", DefClientLockoutThreshold),
			app.NewIntConfigField(
				FldClientLockoutWindowSecs, EnvClientLockoutWindowSecs,
				"Sliding window (seconds) over which failed GetToken attempts are counted", DefClientLockoutWindowSecs),
			app.NewIntConfigField(
				FldClientLockoutDurationSecs, EnvClientLockoutDurationSecs,
				"Lockout duration (seconds) once the GetToken failure threshold is reached", DefClientLockoutDurationSecs),
			app.NewIntConfigField(
				FldEmailCooldownSecs, EnvEmailCooldownSecs,
				"Minimum seconds between outbound verification/reset emails to the same address", DefEmailCooldownSecs),
			app.NewIntConfigField(
				FldRateLimitRPS, EnvRateLimitRPS,
				"Sustained requests/sec allowed per peer IP on the raw gRPC port (coarse fallback safety net)", DefRateLimitRPS),
			app.NewIntConfigField(
				FldRateLimitBurst, EnvRateLimitBurst,
				"Burst allowance per peer IP on the raw gRPC port", DefRateLimitBurst),
			app.NewIntConfigField(
				FldRateLimitIdleTTLSecs, EnvRateLimitIdleTTLSecs,
				"Seconds of inactivity before a peer IP's rate-limit bucket is evicted", DefRateLimitIdleTTLSecs),
		).
		WithDatabase(dbCtor, dbBootstrap).
		WithBackgroundRoutines(
			keyChecker,
			dbMaintenance,
			rateLimitEvictor,
		)

	grpcConfig := app.NewGrpcConfig(
		app.AuthInterceptor|app.ClientInfoInterceptor|app.RateLimitInterceptor,
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

	// The rate limiter's thresholds come from config, which is only parsed
	// once application.Run() starts -- so it's built via an initializer
	// (runs after config parse, before startGrpc reads GrpcConfig.RateLimiter
	// to build the interceptor chain) rather than here.
	application = application.WithInitializers(rateLimiterInitializer(grpcConfig))
	application = application.WithGrpc(grpcConfig)
	application = application.WithHTTP(startWebServer, stopWebServer)
	application.Run()
}

// rateLimiter backs both the gRPC rate-limit interceptor and the eviction
// background routine. Set once by rateLimiterInitializer during app startup
// (before any background routine or the gRPC server start), then only read
// afterward -- see the ordering note on rateLimiterInitializer.
var rateLimiter *ratelimit.Limiter

// rateLimiterInitializer returns an app.Callback that builds the rate
// limiter from parsed config and attaches it to grpcConfig. It must run as
// an initializer (after config parse, before startGrpc) since GrpcConfig's
// interceptor chain is built from grpcConfig.RateLimiter at gRPC server
// startup, and RATE_LIMIT_* values aren't available until config parsing
// happens inside application.Run().
func rateLimiterInitializer(grpcConfig *app.GrpcConfig) app.Callback {
	return func(a app.App) error {
		rps := app.GetConfigField[int](a.Config(), FldRateLimitRPS)
		burst := app.GetConfigField[int](a.Config(), FldRateLimitBurst)
		idleTTLSecs := app.GetConfigField[int](a.Config(), FldRateLimitIdleTTLSecs)
		rateLimiter = ratelimit.New(float64(rps), burst, time.Duration(idleTTLSecs)*time.Second)
		grpcConfig.SetRateLimiter(rateLimiter)
		return nil
	}
}

// rateLimitEvictor is a background routine that periodically prunes idle
// per-IP buckets from rateLimiter, bounding memory under sustained,
// high-cardinality traffic. Runs on a shorter interval than the hourly DB
// maintenance since an in-memory map growing under a live attack needs
// pruning quickly.
func rateLimitEvictor(a app.App) {
	lg := a.Logger().Derive(log.WithFunction("rateLimitEvictor"))
	ctx := a.BackgroundContext()
	defer func() {
		a.BackgroundWaitGroup().Done()
	}()

	ticker := time.NewTicker(5 * time.Minute)
	for {
		select {
		case <-ticker.C:
			if rateLimiter != nil {
				rateLimiter.Evict()
			}
		case <-ctx.Done():
			lg.Infoln("stopping rate limit evictor")
			ticker.Stop()
			return
		}
	}
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

	if err := db.EnsureDatabase(cfg, a.Logger()); err != nil {
		lg.Fatalf("failed to ensure database exists: %v", err)
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
// This includes running pending migrations, creating the initial admin user,
// and ensuring JWT keys exist.
func dbBootstrap(a app.App) error {
	lg := a.Logger().Derive(log.WithFunction("dbBootstrap"))
	dbconn := a.Database().(*db.DB)
	cfg := a.Config()

	if err := dbconn.Migrate(migrations.FS); err != nil {
		lg.Fatalf("failed to run database migrations: %v", err)
	}

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
			if err := dbconn.DoDatabaseMaintenance(ctx); err != nil {
				lg.Errorf("failed to run db maintenance: %v", err)
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
	lg := a.Logger().Derive(log.WithFunction("grpcAuthRegistrar"))
	mailClient := app.GetServiceClient[*mailclient.Client](a, "mailservice")
	mailerAddress := app.GetConfigField[string](a.Config(), FldMailerAddress)
	registrationMode := app.GetConfigField[string](a.Config(), FldRegistrationMode)
	registrationUrl := app.GetConfigField[string](a.Config(), FldRegistrationUrl)
	verificationUrl := app.GetConfigField[string](a.Config(), FldVerificationUrl)
	resetPasswordUrl := app.GetConfigField[string](a.Config(), FldResetPasswordUrl)

	if registrationMode != "open" && registrationMode != "invite_only" {
		lg.Fatalf("invalid REGISTRATION_MODE %q (must be 'open' or 'invite_only')", registrationMode)
	}

	throttle := server.ThrottleConfig{
		LoginMaxAttempts:      app.GetConfigField[int](a.Config(), FldLoginLockoutThreshold),
		LoginWindow:           time.Duration(app.GetConfigField[int](a.Config(), FldLoginLockoutWindowSecs)) * time.Second,
		LoginLockoutDuration:  time.Duration(app.GetConfigField[int](a.Config(), FldLoginLockoutDurationSecs)) * time.Second,
		ClientMaxAttempts:     app.GetConfigField[int](a.Config(), FldClientLockoutThreshold),
		ClientWindow:          time.Duration(app.GetConfigField[int](a.Config(), FldClientLockoutWindowSecs)) * time.Second,
		ClientLockoutDuration: time.Duration(app.GetConfigField[int](a.Config(), FldClientLockoutDurationSecs)) * time.Second,
		EmailCooldown:         time.Duration(app.GetConfigField[int](a.Config(), FldEmailCooldownSecs)) * time.Second,
	}

	srv := server.NewAuthServer(
		a.Database().(*db.DB),
		a.Logger(),
		mailClient,
		mailerAddress,
		registrationMode,
		registrationUrl,
		verificationUrl,
		resetPasswordUrl,
		throttle,
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
// This is used for email verification completion pages and the registration form.
func startWebServer(a app.App) error {
	lg := a.Logger().Derive(log.WithFunction("startWebServer"))
	port := app.GetConfigField[int](a.Config(), app.KeyWebPort)
	prefix := app.GetConfigField[string](a.Config(), app.KeyWebPathPrefix)
	mailClient := app.GetServiceClient[*mailclient.Client](a, "mailservice")
	mailerAddress := app.GetConfigField[string](a.Config(), FldMailerAddress)
	registrationMode := app.GetConfigField[string](a.Config(), FldRegistrationMode)

	// Derive the verify-user URL from web port and path prefix.
	// In production, override REGISTRATION_URL to match the external hostname.
	trimmedPrefix := strings.TrimRight(prefix, "/")
	verifyUserUrl := fmt.Sprintf("http://localhost:%d%s/verify-user", port, trimmedPrefix)

	regCfg := &web.RegisterConfig{
		MailClient:       mailClient,
		MailerAddress:    mailerAddress,
		RegistrationMode: registrationMode,
		VerifyUserUrl:    verifyUserUrl,
	}

	ws := web.New(
		fmt.Sprintf("0.0.0.0:%d", port),
		prefix, a.Database().(*db.DB),
		a.Logger(), regCfg)
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
