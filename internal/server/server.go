// Package server implements the gRPC server for the authentication service.
//
// This package provides the AuthServer and HealthServer implementations that handle
// all authentication-related RPC endpoints including user login, registration,
// token management, password operations, and service client authentication.
//
// # Endpoint Security
//
// Endpoints are registered with different security levels in init():
//   - Public: No authentication required (Login, Register, PublicKeys, etc.)
//   - Unverified: Requires valid JWT but email verification not required
//   - Admin: Requires valid JWT with admin privileges
//   - ServiceClient: Requires service client token with specific scopes
//
// # Cookie Handling
//
// For HTTP clients, refresh tokens are automatically set as HTTP-only cookies
// via the CookieForwarder function registered with grpc-gateway.
package server

import (
	"github.com/swayrider/grpcclients/mailclient"
	authv1 "github.com/swayrider/protos/auth/v1"
	healthv1 "github.com/swayrider/protos/health/v1"
	"github.com/swayrider/authservice/internal/db"
	log "github.com/swayrider/swlib/logger"
	"github.com/swayrider/swlib/security"
)

// init registers all endpoint security configurations.
// This determines which endpoints require authentication and at what level.
func init() {
	// AuthService Endpoints
	// ---------------------

	// ChangeAccountType - Admin only: modify user account levels
	security.AdminEndpoint("/auth.v1.AuthService/ChangeAccountType")

	// ChangePassword - Authenticated users can change their own password
	security.UnverifiedEndpoint("/auth.v1.AuthService/ChangePassword")

	// CheckPasswordStrength - Public: validate password entropy
	security.PublicEndpoint("/auth.v1.AuthService/CheckPasswordStrength")

	// CheckVerificationToken - Public: verify email verification tokens
	security.PublicEndpoint("/auth.v1.AuthService/CheckVerificationToken")

	// CreateAdmin - Admin only: create new admin users
	security.AdminEndpoint("/auth.v1.AuthService/CreateAdmin")

	// CreateServiceClient - Admin only: register service-to-service clients
	security.AdminEndpoint("/auth.v1.AuthService/CreateServiceClient")

	// CreateVerificationToken - Unverified users only (denied for verified users)
	security.UnverifiedEndpoint("/auth.v1.AuthService/CreateVerificationToken")
	security.DenyVerifiedEndpoint("/auth.v1.AuthService/CreateVerificationToken")

	// DeleteServiceClient - Admin only: remove service clients
	security.AdminEndpoint("/auth.v1.AuthService/DeleteServiceClient")

	// GetToken - Public: service client authentication (uses client credentials)
	security.PublicEndpoint("/auth.v1.AuthService/GetToken")

	// ListServiceClients - Admin only: enumerate service clients
	security.AdminEndpoint("/auth.v1.AuthService/ListServiceClients")

	// Login - Public: user authentication with email/password
	security.PublicEndpoint("/auth.v1.AuthService/Login")

	// Logout - Public: invalidate refresh token
	security.PublicEndpoint("/auth.v1.AuthService/Logout")

	// PublicKeys - Public: retrieve JWT verification keys
	security.PublicEndpoint("/auth.v1.AuthService/PublicKeys")

	// Refresh - Public: exchange refresh token for new token pair
	security.PublicEndpoint("/auth.v1.AuthService/Refresh")

	// Register - Public: create new user account
	security.PublicEndpoint("/auth.v1.AuthService/Register")

	// RequestPasswordReset - Public: initiate password reset flow
	security.PublicEndpoint("/auth.v1.AuthService/RequestPasswordReset")

	// ResetPassword - Public: complete password reset with token
	security.PublicEndpoint("/auth.v1.AuthService/ResetPassword")

	// VerifyEmail - Public: request new verification email
	security.PublicEndpoint("/auth.v1.AuthService/VerifyEmail")

	// WhoAmI - Authenticated: get current user info
	security.UnverifiedEndpoint("/auth.v1.AuthService/WhoAmI")

	// WhoIs - Admin or service client with user:read scope: lookup any user
	security.AdminEndpoint("/auth.v1.AuthService/WhoIs")
	security.ServiceClientEndpoint("/auth.v1.AuthService/WhoIs", []string{
		"user:read",
	})

	// HealthService Endpoints
	// -----------------------

	// Check - Public: detailed health status
	security.PublicEndpoint("/health.v1.HealthService/Check")

	// Ping - Public: simple liveness check
	security.PublicEndpoint("/health.v1.HealthService/Ping")
}

// AuthServer implements the AuthService gRPC interface.
// It handles all authentication operations including user login, registration,
// token management, and service client authentication.
type AuthServer struct {
	authv1.UnimplementedAuthServiceServer
	dbConn        *db.DB             // Database connection for user/token storage
	mailClient    *mailclient.Client // Client for sending verification/reset emails
	mailerAddress string             // From address for outgoing emails
	l             *log.Logger        // Logger instance
}

// HealthServer implements the HealthService gRPC interface.
// It provides health check endpoints for monitoring and load balancing.
type HealthServer struct {
	healthv1.UnimplementedHealthServiceServer
	l *log.Logger // Logger instance
}

// NewAuthServer creates a new AuthServer
func NewAuthServer(
	conn *db.DB, lgr *log.Logger,
	mailClient *mailclient.Client,
	mailerAddress string,
) *AuthServer {
	return &AuthServer{
		dbConn:        conn,
		mailClient:    mailClient,
		mailerAddress: mailerAddress,
		l: lgr.Derive(
			log.WithComponent("AuthServer"),
			log.WithFunction("NewAuthServer"),
		),
	}
}

// DB returns the database connection
func (s *AuthServer) DB() *db.DB {
	return s.dbConn
}

// Logger returns the logger
func (s *AuthServer) Logger() *log.Logger {
	return s.l
}

// NewHealthServer creates a new HealthServer
func NewHealthServer(lgr *log.Logger) *HealthServer {
	return &HealthServer{
		l: lgr.Derive(
			log.WithComponent("HealthServer"),
			log.WithFunction("NewHealthServer"),
		),
	}
}

// Logger returns the logger
func (s *HealthServer) Logger() *log.Logger {
	return s.l
}
