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
// Background goroutines run continuously:
//   - keyChecker: Rotates JWT signing keys before expiration (hourly check)
//   - dbMaintenance: Cleans up expired tokens and stale audit_log rows (hourly)
//   - auditFlusher: Drains the async audit_log writer to the database
package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/swayrider/authservice/internal/db"
	"github.com/swayrider/authservice/internal/server"
	"github.com/swayrider/authservice/internal/web"
	"github.com/swayrider/authservice/migrations"
	"github.com/swayrider/grpcclients"
	"github.com/swayrider/grpcclients/mailclient"
	authv1 "github.com/swayrider/protos/auth/v1"
	healthv1 "github.com/swayrider/protos/health/v1"
	"github.com/swayrider/swlib/http/cookies"
	log "github.com/swayrider/swlib/logger"
	"google.golang.org/grpc"

	"github.com/swayrider/swlib/app"
	"github.com/swayrider/swlib/crypto"
	"github.com/swayrider/swlib/encryption"
	flg "github.com/swayrider/swlib/flag"
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

	FldLoginLockoutThreshold      = "login-lockout-threshold"
	FldLoginLockoutWindowSecs     = "login-lockout-window-secs"
	FldLoginLockoutDurationSecs   = "login-lockout-duration-secs"
	FldClientLockoutThreshold     = "client-lockout-threshold"
	FldClientLockoutWindowSecs    = "client-lockout-window-secs"
	FldClientLockoutDurationSecs  = "client-lockout-duration-secs"
	FldEmailCooldownSecs          = "email-cooldown-secs"
	FldEmailIPMaxAttempts         = "email-ip-max-attempts"
	FldEmailIPWindowSecs          = "email-ip-window-secs"
	FldEmailIPLockoutDurationSecs = "email-ip-lockout-duration-secs"

	EnvLoginLockoutThreshold      = "LOGIN_LOCKOUT_THRESHOLD"
	EnvLoginLockoutWindowSecs     = "LOGIN_LOCKOUT_WINDOW_SECS"
	EnvLoginLockoutDurationSecs   = "LOGIN_LOCKOUT_DURATION_SECS"
	EnvClientLockoutThreshold     = "CLIENT_LOCKOUT_THRESHOLD"
	EnvClientLockoutWindowSecs    = "CLIENT_LOCKOUT_WINDOW_SECS"
	EnvClientLockoutDurationSecs  = "CLIENT_LOCKOUT_DURATION_SECS"
	EnvEmailCooldownSecs          = "EMAIL_COOLDOWN_SECS"
	EnvEmailIPMaxAttempts         = "EMAIL_IP_MAX_ATTEMPTS"
	EnvEmailIPWindowSecs          = "EMAIL_IP_WINDOW_SECS"
	EnvEmailIPLockoutDurationSecs = "EMAIL_IP_LOCKOUT_DURATION_SECS"

	DefLoginLockoutThreshold      = 5
	DefLoginLockoutWindowSecs     = 900
	DefLoginLockoutDurationSecs   = 900
	DefClientLockoutThreshold     = 5
	DefClientLockoutWindowSecs    = 900
	DefClientLockoutDurationSecs  = 900
	DefEmailCooldownSecs          = 60
	DefEmailIPMaxAttempts         = 20
	DefEmailIPWindowSecs          = 900
	DefEmailIPLockoutDurationSecs = 900

	FldHealthProbeTtlSecs = "health-probe-ttl-secs"
	EnvHealthProbeTTLSecs = "HEALTH_PROBE_TTL_SECS"
	DefHealthProbeTtlSecs = 15

	FldAuditRetentionDays = "audit-retention-days"
	FldAuditBufferSize    = "audit-buffer-size"

	EnvAuditRetentionDays = "AUDIT_RETENTION_DAYS"
	EnvAuditBufferSize    = "AUDIT_BUFFER_SIZE"

	DefAuditRetentionDays = 90
	DefAuditBufferSize    = 1000

	FldJwtKeyRetentionDays = "jwt-key-retention-days"
	EnvJwtKeyRetentionDays = "JWT_KEY_RETENTION_DAYS"
	DefJwtKeyRetentionDays = 7

	FldEncryptionMasterKey         = "encryption-master-key"
	FldEncryptionMasterKeyPrevious = "encryption-master-key-previous"

	EnvEncryptionMasterKey         = "ENCRYPTION_MASTER_KEY"
	EnvEncryptionMasterKeyPrevious = "ENCRYPTION_MASTER_KEY_PREVIOUS"

	DefEncryptionMasterKey = ""
)

// DefEncryptionMasterKeyPrevious is the default for FldEncryptionMasterKeyPrevious:
// no retired master keys configured. Not a const, since ConfigField defaults
// for string-array fields are typed []string.
var DefEncryptionMasterKeyPrevious []string

func main() {
	if ns := os.Getenv("COOKIE_NAMESPACE"); ns != "" {
		cookies.SetNamespace(ns)
	}

	sameSite, err := cookies.ParseSameSite(os.Getenv("COOKIE_SAMESITE"))
	if err != nil {
		log.Warnf("invalid COOKIE_SAMESITE %q, using 'strict': %v",
			os.Getenv("COOKIE_SAMESITE"), err)
	}
	cookies.SetDefaultSameSite(sameSite)

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
				FldEmailIPMaxAttempts, EnvEmailIPMaxAttempts,
				"Outbound verification/reset emails allowed per source IP before it is locked out (defense-in-depth against spraying many distinct addresses)", DefEmailIPMaxAttempts),
			app.NewIntConfigField(
				FldEmailIPWindowSecs, EnvEmailIPWindowSecs,
				"Sliding window (seconds) over which per-IP outbound email attempts are counted", DefEmailIPWindowSecs),
			app.NewIntConfigField(
				FldEmailIPLockoutDurationSecs, EnvEmailIPLockoutDurationSecs,
				"Lockout duration (seconds) once the per-IP outbound email threshold is reached", DefEmailIPLockoutDurationSecs),
			app.NewIntConfigField(
				FldHealthProbeTtlSecs, EnvHealthProbeTTLSecs,
				"How long in seconds a health probe result is cached before re-probing the database",
				DefHealthProbeTtlSecs),
			app.NewIntConfigField(
				FldAuditRetentionDays, EnvAuditRetentionDays,
				"Days to retain audit_log rows before the hourly maintenance routine deletes them",
				DefAuditRetentionDays),
			app.NewIntConfigField(
				FldAuditBufferSize, EnvAuditBufferSize,
				"Buffer size of the async audit_log writer; events are dropped (and a warning logged) if the buffer is full",
				DefAuditBufferSize),
			app.NewIntConfigField(
				FldJwtKeyRetentionDays, EnvJwtKeyRetentionDays,
				"Days an expired jwt_keys row is kept (forensics/clock-skew margin) before the hourly maintenance routine deletes it",
				DefJwtKeyRetentionDays),
			app.NewStringConfigField(
				FldEncryptionMasterKey, EnvEncryptionMasterKey,
				"Base64-encoded 256-bit master key used to encrypt the JWT signing private key at rest (required; generate with `openssl rand -base64 32`)",
				DefEncryptionMasterKey),
			app.NewStringArrConfigField(
				FldEncryptionMasterKeyPrevious, EnvEncryptionMasterKeyPrevious,
				"Comma-separated list of retired base64-encoded master keys, used only to decrypt jwt_keys rows encrypted before a master key rotation",
				DefEncryptionMasterKeyPrevious),
		).
		WithConfigFields(app.RateLimitConfigFields()...).
		WithDatabase(dbCtor, dbBootstrap)

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
	grpcConfig.SetAllowCredentials(true)

	// The rate limiter's thresholds come from config, which is only parsed
	// once application.Run() starts -- so it's built via an initializer
	// (runs after config parse, before startGrpc reads GrpcConfig.RateLimiter
	// to build the interceptor chain) rather than here.
	application = application.
		WithBackgroundRoutines(
			keyChecker,
			dbMaintenance,
			auditFlusher,
			app.RateLimitEvictor(grpcConfig),
		).
		WithInitializers(app.RateLimiterInitializer(grpcConfig)).
		WithGrpc(grpcConfig).
		WithHTTP(startWebServer, stopWebServer)
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

	rawKey := app.GetConfigField[string](a.Config(), FldEncryptionMasterKey)
	masterKey, err := encryption.ParseMasterKey(rawKey)
	if err != nil {
		lg.Fatalf("invalid %s: %v", EnvEncryptionMasterKey, err)
	}

	var previousKeys [][]byte
	for _, raw := range app.GetConfigField[flg.StringArr](a.Config(), FldEncryptionMasterKeyPrevious) {
		if raw == "" {
			continue // unset case: GetAsStringArr on an empty fallback yields [""]
		}
		prevKey, err := encryption.ParseMasterKey(raw)
		if err != nil {
			lg.Fatalf("invalid entry in %s: %v", EnvEncryptionMasterKeyPrevious, err)
		}
		previousKeys = append(previousKeys, prevKey)
	}
	cfg.EncryptionKeyRing = encryption.NewKeyRing(masterKey, previousKeys)

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

// dbMaintenance is a background routine that cleans up expired tokens,
// stale audit_log rows, and expired jwt_keys rows. It runs hourly and
// removes expired refresh tokens, verification tokens, password reset
// tokens, audit_log rows older than AUDIT_RETENTION_DAYS, and jwt_keys rows
// expired more than JWT_KEY_RETENTION_DAYS ago from the database.
func dbMaintenance(a app.App) {
	lg := a.Logger().Derive(log.WithFunction("dbMaintenance"))
	dbconn := a.Database().(*db.DB)
	ctx := a.BackgroundContext()
	auditRetentionDays := app.GetConfigField[int](a.Config(), FldAuditRetentionDays)
	jwtKeyRetentionDays := app.GetConfigField[int](a.Config(), FldJwtKeyRetentionDays)
	defer func() {
		a.BackgroundWaitGroup().Done()
	}()

	ticker := time.NewTicker(1 * time.Hour)
	for {
		select {
		case <-ticker.C:
			if err := dbconn.DoDatabaseMaintenance(ctx, auditRetentionDays, jwtKeyRetentionDays); err != nil {
				lg.Errorf("failed to run db maintenance: %v", err)
			}
		case <-ctx.Done():
			lg.Infoln("stopping db maintenance")
			ticker.Stop()
			return
		}
	}
}

// auditWriterOnce/auditWriterInst back sharedAuditWriter: the AuditWriter
// must be a single shared instance between grpcAuthRegistrar (which hands it
// to AuthServer for emitting events) and auditFlusher (which drains it to
// the database), but swlib/app doesn't guarantee which of the two callbacks
// runs first, and neither can read AUDIT_BUFFER_SIZE from config until
// invoked by app.Run(). Lazy-init on first use sidesteps both problems.
var (
	auditWriterOnce sync.Once
	auditWriterInst *server.AuditWriter
)

func sharedAuditWriter(a app.App) *server.AuditWriter {
	auditWriterOnce.Do(func() {
		bufSize := app.GetConfigField[int](a.Config(), FldAuditBufferSize)
		auditWriterInst = server.NewAuditWriter(bufSize, a.Logger())
	})
	return auditWriterInst
}

// auditFlusher is a background routine that drains the shared AuditWriter's
// buffer, writing each event to the database. Unlike keyChecker/dbMaintenance
// it has no ticker -- it drains continuously as events arrive rather than on
// an interval -- and performs a short bounded drain of any remaining
// buffered events on shutdown before returning.
func auditFlusher(a app.App) {
	lg := a.Logger().Derive(log.WithFunction("auditFlusher"))
	dbconn := a.Database().(*db.DB)
	ch := sharedAuditWriter(a).Chan()
	ctx := a.BackgroundContext()
	defer func() {
		a.BackgroundWaitGroup().Done()
	}()

	for {
		select {
		case ev := <-ch:
			if err := dbconn.InsertAuditEvent(ctx, ev); err != nil {
				lg.Warnf("failed to write audit event: %v", err)
			}
		case <-ctx.Done():
			lg.Infoln("stopping audit flusher, draining buffered events")
			drainCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
		drain:
			for {
				select {
				case ev := <-ch:
					if err := dbconn.InsertAuditEvent(drainCtx, ev); err != nil {
						lg.Warnf("failed to write audit event during drain: %v", err)
					}
				default:
					break drain
				}
			}
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
		LoginMaxAttempts:       app.GetConfigField[int](a.Config(), FldLoginLockoutThreshold),
		LoginWindow:            time.Duration(app.GetConfigField[int](a.Config(), FldLoginLockoutWindowSecs)) * time.Second,
		LoginLockoutDuration:   time.Duration(app.GetConfigField[int](a.Config(), FldLoginLockoutDurationSecs)) * time.Second,
		ClientMaxAttempts:      app.GetConfigField[int](a.Config(), FldClientLockoutThreshold),
		ClientWindow:           time.Duration(app.GetConfigField[int](a.Config(), FldClientLockoutWindowSecs)) * time.Second,
		ClientLockoutDuration:  time.Duration(app.GetConfigField[int](a.Config(), FldClientLockoutDurationSecs)) * time.Second,
		EmailCooldown:          time.Duration(app.GetConfigField[int](a.Config(), FldEmailCooldownSecs)) * time.Second,
		EmailIPMaxAttempts:     app.GetConfigField[int](a.Config(), FldEmailIPMaxAttempts),
		EmailIPWindow:          time.Duration(app.GetConfigField[int](a.Config(), FldEmailIPWindowSecs)) * time.Second,
		EmailIPLockoutDuration: time.Duration(app.GetConfigField[int](a.Config(), FldEmailIPLockoutDurationSecs)) * time.Second,
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
		sharedAuditWriter(a),
	)
	authv1.RegisterAuthServiceServer(r, srv)
}

// grpcHealthRegistrar registers the HealthService gRPC server with the registrar.
func grpcHealthRegistrar(r grpc.ServiceRegistrar, a app.App) {
	probeTTLSecs := app.GetConfigField[int](a.Config(), FldHealthProbeTtlSecs)
	srv := server.NewHealthServer(a.Database().SqlDB(), time.Duration(probeTTLSecs)*time.Second, a.Logger())
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
