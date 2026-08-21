// authentication.go implements user and service client authentication endpoints.
//
// This file contains the Login, Logout, Refresh, and GetToken endpoints, as well as
// helper functions for token generation and cookie handling.

package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
	authv1 "github.com/swayrider/protos/auth/v1"
	"github.com/swayrider/authservice/internal/db"
	"github.com/swayrider/authservice/internal/model"
	"github.com/swayrider/swlib/crypto"
	"github.com/swayrider/swlib/http/cookies"
	"github.com/swayrider/swlib/jwt"
	log "github.com/swayrider/swlib/logger"
	"github.com/swayrider/swlib/security"
)

// ContextKey is a type for context value keys to avoid collisions.
type ContextKey string

const (
	// RememberMeKey is the context key for storing the remember-me preference.
	RememberMeKey ContextKey = "rememberMe"
)

// GetRememberMe extracts the remember-me preference from the context.
// Returns false if the value is not set.
func GetRememberMe(ctx context.Context) (rememberMe bool) {
	iface := ctx.Value(RememberMeKey)
	if iface != nil {
		rememberMe = iface.(bool)
	}
	return
}

// CookieForwarder is a grpc-gateway response modifier that handles refresh token cookies.
// It automatically sets or clears the refresh_token HTTP-only cookie based on the response type:
//   - LoginResponse/RefreshResponse/VerifyMFAResponse: Sets the cookie with the new refresh token
//   - LogoutResponse: Clears the cookie
//
// A response with an empty refresh token (e.g. a pending MFA login response
// that carries only a challenge token) never sets a cookie.
//
// The cookie lifetime is extended if the remember-me header is set to "true".
func CookieForwarder(ctx context.Context, w http.ResponseWriter, resp proto.Message) error {
	setCookie := false
	unsetCookie := false
	token := ""
	switch r := resp.(type) {
	case *authv1.LoginResponse:
		setCookie = true
		token = r.RefreshToken
	case *authv1.RefreshResponse:
		setCookie = true
		token = r.RefreshToken
	case *authv1.VerifyMFAResponse:
		setCookie = true
		token = r.RefreshToken
	case *authv1.LogoutResponse:
		unsetCookie = true
	}

	// A response with no refresh token (e.g. a pending MFA login that only
	// carries a challenge token) must never set an empty cookie.
	if setCookie && token == "" {
		setCookie = false
	}

	if setCookie {
		rememberMe := false
		md, ok := runtime.ServerMetadataFromContext(ctx)
		if ok {
			if vals := md.HeaderMD.Get("remember-me"); len(vals) > 0 {
				rememberMe = vals[0] == "true"
				md.HeaderMD.Delete("remember-me")
			}
		}

		opts := cookies.NewCookieOptsFromContext(ctx)
		if rememberMe {
			opts.SetTTL(cookies.TTLRemeberLogin)
		}
		refreshCookie := cookies.NewServerCookie(
			"refresh_token", []byte(token), opts)
		http.SetCookie(w, refreshCookie)
	}

	if unsetCookie {
		opts := cookies.NewCookieOptsFromContext(ctx)
		refreshCookie := cookies.ClearCookie(
			"refresh_token", opts)
		http.SetCookie(w, refreshCookie)
	}

	return nil
}

// CookieHeaderMatcher is a grpc-gateway header matcher that forwards cookie
// headers and the caller's original scheme. This allows the refresh token to
// be read from cookies in addition to the request body, and lets
// ClientInfoInterceptor correctly derive security.SecureKey for the cookies
// CookieForwarder issues (grpc-gateway's DefaultHeaderMatcher drops
// X-Forwarded-Proto by default).
func CookieHeaderMatcher(header string) (string, bool) {
	switch {
	case strings.EqualFold(header, "cookie"):
		return "cookie", true
	case strings.EqualFold(header, "x-forwarded-proto"):
		return "x-forwarded-proto", true
	}
	return runtime.DefaultHeaderMatcher(header)
}

// Login logs in a user
//
// Parameters:
//   - ctx: The context of the request
//   - req: The request to log in a User
//
// Returns:
//   - *authv1.LoginResponse: The response from the login request
//   - error: An error if the request fails
func (s *AuthServer) Login(
	ctx context.Context,
	req *authv1.LoginRequest,
) (*authv1.LoginResponse, error) {
	lg := s.Logger().Derive(log.WithFunction("Login"))

	identifier := normalizeIdentifier(req.Email)

	// Checked before the account is even looked up, and keyed the same way
	// regardless of whether it exists, so a locked-out attempt and an
	// unknown-account attempt are indistinguishable from the caller's
	// perspective -- preserving the uniform "invalid email or password"
	// anti-enumeration invariant this handler already relies on below.
	if s.isLocked(ctx, db.ScopeLogin, identifier) {
		return nil, status.Error(
			codes.Unauthenticated,
			"invalid email or password")
	}

	u, err := s.DB().GetUserByEmail(ctx, req.Email)
	if err != nil {
		lg.Debugf("user %s failed a login attempt: %v", req.Email, err)
		if errors.Is(err, db.ErrUserNotFound) {
			s.recordLoginAttempt(ctx, identifier, false)
			s.auditLoginFailure(ctx, req.Email, "user_not_found")
			return nil, status.Error(
				codes.Unauthenticated,
				"invalid email or password")
		}
		// Not a credential-guessing signal -- an infrastructure error here
		// must not be recordable, or an attacker could deliberately trip DB
		// errors to lock out a victim's account.
		return nil, status.Error(codes.Internal, "internal error")
	}

	if !u.PasswordHash.Valid {
		lg.Debugf("user %s failed a login attempt: invalid password", req.Email)
		s.recordLoginAttempt(ctx, identifier, false)
		s.auditLoginFailure(ctx, req.Email, "invalid_password_state")
		return nil, status.Error(
			codes.Unauthenticated,
			"invalid email or password")
	}

	var passwordOk bool
	passwordOk, err = crypto.VerifyPassword(u.PasswordHash.String, req.Password)
	if err != nil {
		lg.Debugf("user %s failed a login attempt: %v", req.Email, err)
		s.recordLoginAttempt(ctx, identifier, false)
		s.auditLoginFailure(ctx, req.Email, "verify_error")
		return nil, status.Error(
			codes.Unauthenticated,
			"invalid email or password")
	}
	if !passwordOk {
		lg.Debugf("user %s failed a login attempt: invalid password", req.Email)
		s.recordLoginAttempt(ctx, identifier, false)
		s.auditLoginFailure(ctx, req.Email, "wrong_password")
		return nil, status.Error(
			codes.Unauthenticated,
			"invalid email or password")
	}

	s.recordLoginAttempt(ctx, identifier, true)
	s.auditLoginSuccess(ctx, u.ID, u.Email)

	// MFA gate: when the account has MFA enabled, do not issue tokens yet.
	// Issue a short-lived single-use challenge token instead; the caller
	// exchanges it (plus a TOTP/backup code) via VerifyMFA. This lookup runs
	// only after a correct password, and the response shape is uniform for
	// MFA/non-MFA accounts (the client branches on mfa_required), so it is
	// not an account-enumeration signal. When the global switch is off, the
	// MFA step is simply bypassed.
	if s.mfa.Enabled {
		enabled, err := s.DB().GetMFAStatus(ctx, u.ID)
		if err != nil {
			return nil, status.Error(codes.Internal, "internal error")
		}
		if enabled {
			rawToken, err := s.createMFAChallenge(ctx, u.ID)
			if err != nil {
				lg.Errorf("failed to create MFA challenge: %v", err)
				return nil, status.Error(codes.Internal, "internal error")
			}
			return &authv1.LoginResponse{MfaRequired: true, MfaToken: rawToken}, nil
		}
	}

	origIp, _ := security.GetOrigIp(ctx)
	userAgent, _ := security.GetUserAgent(ctx)
	// Normalize to a single IP so the stored token binding is unambiguous,
	// even if the context value is a comma-joined chain.
	accessToken, refreshToken, err := s.createAuthTokens(ctx, u, model.FirstIP(origIp), userAgent)
	if err != nil {
		return nil, err
	}

	if err = grpc.SetHeader(ctx, metadata.Pairs(
		"remember-me", fmt.Sprintf("%v", req.RememberMe))); err != nil {
		lg.Warnf("failed to set remember-me header: %v", err)
	}

	lg.Debugf("user logged in with ID: %s", u.ID)
	return &authv1.LoginResponse{
		AccessToken:  string(accessToken),
		RefreshToken: refreshToken.Token,
	}, nil
}

// Logout invalidates a user's refresh token, ending their session.
//
// The refresh token can be provided either in the request body or via cookie.
// Cookie-based tokens take precedence over request body tokens.
//
// Returns:
//   - codes.Unauthenticated: If the refresh token cannot be deleted
func (s *AuthServer) Logout(
	ctx context.Context,
	req *authv1.LogoutRequest,
) (*authv1.LogoutResponse, error) {
	lg := s.Logger().Derive(log.WithFunction("Logout"))

	// Try to get token from cookie first, then fall back to request body
	refreshToken, _ := security.GetRefreshToken(ctx)
	if refreshToken == "" {
		refreshToken = req.RefreshToken
	}

	err := s.DB().DeleteRefreshToken(ctx, refreshToken)
	if err != nil {
		lg.Errorf("could not delete refresh token: %v", err)
		return nil, status.Errorf(
			codes.Unauthenticated,
			"could not delete refresh token")
	}

	s.auditLogout(ctx)
	return &authv1.LogoutResponse{}, nil
}

// GetToken authenticates a service client and returns an access token.
//
// This endpoint implements the client credentials OAuth2 flow for service-to-service
// authentication. The client must provide valid credentials (clientId and clientSecret).
//
// Scope handling:
//   - If client has "*" scope, all requested scopes are granted
//   - If request contains "*" scope, all client's scopes are granted
//   - Otherwise, only the intersection of requested and client scopes is granted
//
// Returns:
//   - codes.NotFound: If the client ID doesn't exist
//   - codes.Unauthenticated: If the client secret is invalid
func (s *AuthServer) GetToken(
	ctx context.Context,
	req *authv1.GetTokenRequest,
) (*authv1.GetTokenResponse, error) {
	lg := s.Logger().Derive(log.WithFunction("GetToken"))

	// client IDs are generated, not user-typed -- no normalization needed.
	if s.isLocked(ctx, db.ScopeGetToken, req.ClientId) {
		return nil, status.Error(
			codes.Unauthenticated,
			"service client authentication error")
	}

	clnt, err := s.DB().GetServiceClientByID(ctx, req.ClientId)
	if err != nil {
		lg.Debugf("service client %s not found: %v", req.ClientId, err)
		if errors.Is(err, db.ErrServiceClientNotFound) {
			s.recordClientAttempt(ctx, req.ClientId, false)
			s.auditServiceClientAuth(ctx, req.ClientId, false, "client_not_found")
			return nil, status.Error(
				codes.Unauthenticated,
				"service client authentication error")
		}
		// Infrastructure error -- not recorded, same reasoning as Login.
		return nil, status.Error(codes.Internal, "internal error")
	}

	if !clnt.ClientSecretHash.Valid {
		lg.Debugf("service client %s not found: invalid secret", req.ClientId)
		s.recordClientAttempt(ctx, req.ClientId, false)
		s.auditServiceClientAuth(ctx, req.ClientId, false, "invalid_secret_state")
		return nil, status.Error(
			codes.Unauthenticated,
			"service client authentication error")
	}

	// Verify client secret using Argon2id
	var secretOk bool
	secretOk, err = crypto.VerifyPassword(clnt.ClientSecretHash.String, req.ClientSecret)
	if err != nil {
		lg.Debugf("service client %s authentication error: %v", req.ClientId, err)
		s.recordClientAttempt(ctx, req.ClientId, false)
		s.auditServiceClientAuth(ctx, req.ClientId, false, "verify_error")
		return nil, status.Error(
			codes.Unauthenticated,
			"service client authentication error")
	}
	if !secretOk {
		lg.Debugf("service client %s authentication error: invalid secret", req.ClientId)
		s.recordClientAttempt(ctx, req.ClientId, false)
		s.auditServiceClientAuth(ctx, req.ClientId, false, "wrong_secret")
		return nil, status.Error(
			codes.Unauthenticated,
			"service client authentication error")
	}

	s.recordClientAttempt(ctx, req.ClientId, true)
	s.auditServiceClientAuth(ctx, req.ClientId, true, "")

	accessToken, validUntil, grantedScopes, err := s.createServiceToken(ctx, clnt, req.Scopes)
	if err != nil {
		return nil, err
	}
	lg.Debugf("service client %s authenticated", req.ClientId)

	return &authv1.GetTokenResponse{
		AccessToken: string(accessToken),
		Scopes:      grantedScopes,
		ValidUntil:  timestamppb.New(*validUntil),
	}, nil
}

// Refresh exchanges a valid refresh token for a new access/refresh token pair.
//
// This implements refresh token rotation: the old refresh token is invalidated
// and a new one is issued. The refresh token can be provided via cookie or request body.
//
// Security validations:
//   - Token must exist in the database
//   - Token must be valid (not revoked/expired) and match the user agent
//   - The IP is checked as a soft anomaly signal only: a mismatch is logged,
//     never rejected (mobile clients legitimately change IP between requests)
//   - The old token is atomically consumed (read-and-deleted in one statement)
//     before verification, so it cannot be replayed by a concurrent request
//     even if verification then fails
//
// Returns:
//   - codes.Unauthenticated: If the refresh token is invalid or verification fails
func (s *AuthServer) Refresh(
	ctx context.Context,
	req *authv1.RefreshRequest,
) (*authv1.RefreshResponse, error) {
	lg := s.Logger().Derive(log.WithFunction("Refresh"))

	// Extract client identifiers for token binding verification
	origIp, _ := security.GetOrigIp(ctx)
	userAgent, _ := security.GetUserAgent(ctx)
	origIp = model.FirstIP(origIp)
	refreshToken, _ := security.GetRefreshToken(ctx)
	if refreshToken == "" {
		refreshToken = req.RefreshToken
	}

	// Atomically retrieve and invalidate the refresh token (rotation). A
	// single statement closes the TOCTOU window: concurrent refreshes of the
	// same token cannot both succeed, since only one DELETE finds a row.
	token, err := s.DB().ConsumeRefreshToken(ctx, refreshToken)
	if err != nil {
		lg.Errorf("could not consume refresh token: %v", err)
		s.auditRefreshFailure(ctx, nil, "token_not_found")
		return nil, status.Errorf(
			codes.Unauthenticated,
			"could not get refresh token")
	}

	// Verify token validity (revoked/expired/user agent). The IP is NOT
	// gated: mobile clients legitimately change IP between login and
	// refresh, so a mismatch is logged as an anomaly signal and the refresh
	// proceeds. The rotated token below is re-bound to the current IP.
	err = token.Verify(userAgent)
	if err != nil {
		lg.Errorf("could not verify refresh token: %v", err)
		s.auditRefreshFailure(ctx, &token.UserId, "verify_failed")
		return nil, status.Errorf(
			codes.Unauthenticated,
			"could not verify refresh token")
	}
	if !token.MatchesIP(origIp) {
		lg.Warnf("refresh token IP mismatch user=%s stored=%q got=%q",
			token.UserId, token.Ip, origIp)
	}

	// Load user data for new token generation
	user, err := s.DB().GetUserByID(ctx, token.UserId)
	if err != nil {
		lg.Errorf("could not get user: %v", err)
		return nil, status.Errorf(
			codes.Unauthenticated,
			"could not get user")
	}

	// Generate new token pair
	accessToken, newRefreshToken, err := s.createAuthTokens(
		ctx, user, origIp, userAgent)
	if err != nil {
		log.Debugf("could not create auth tokens: %v", err)
		return nil, err
	}

	lg.Debugf("user refreshed with ID: %s", user.ID)
	s.auditRefreshSuccess(ctx, user.ID)
	return &authv1.RefreshResponse{
		AccessToken:  string(accessToken),
		RefreshToken: newRefreshToken.Token,
	}, nil
}

// createAuthTokens generates a new JWT access token and refresh token for a user.
//
// The access token contains:
//   - Standard JWT claims (iss, sub, aud, exp, iat, jti)
//   - OpenID claims (email, email_verified, updated_time, auth_time)
//   - SwayRider claims (is_admin, account_level)
//
// The refresh token is stored in the database and bound to:
//   - The JWT ID (jti) of the access token
//   - The client's IP address
//   - The client's user agent
//
// This binding allows detection of token theft (if refresh is attempted from different client).
func (s *AuthServer) createAuthTokens(
	ctx context.Context,
	user *model.UserInternal,
	origIp string,
	userAgent string,
) (jwt.AccessToken, *model.RefreshToken, error) {
	lg := s.Logger().Derive(log.WithFunction("createAuthTokens"))

	// Get the current signing key (supports rolling key rotation)
	pk, err := s.DB().GetSigningKey(ctx)
	if err != nil {
		lg.Errorf("unable to retrieve signing key: %v", err)
		return "", nil, status.Errorf(
			codes.Internal,
			"unable to retrieve signing key")
	}

	// Build OpenID Connect standard claims
	openIDClaims := &jwt.OpenIDClaims{
		Email:         &user.Email,
		EmailVerified: &user.IsVerified,
	}
	openIDClaims.SetUpdatedTime(user.UpdatedAt)
	openIDClaims.SetAuthTime(time.Now())

	// Build SwayRider-specific claims
	swayriderClaims := jwt.NewSwayRiderUserClaims(
		user.IsAdmin,
		user.AccountLevel,
	)

	// Generate the signed JWT access token
	jwtID, accessToken, _, err := jwt.GenerateToken(
		user.ID, openIDClaims, swayriderClaims, pk, jwt.DefaultTTL)
	if err != nil {
		lg.Errorf("Unable to generate access token: %v", err)
		return "", nil, status.Errorf(
			codes.Internal,
			"unable to generate access token")
	}

	// Create and store refresh token with client binding
	refreshToken, err := s.DB().CreateRefreshToken(
		ctx, &user.User, jwtID, origIp, userAgent)
	if err != nil {
		lg.Debugf("Unable to generate access token: %v", err)
		return "", nil, status.Errorf(
			codes.Internal,
			"unable to generate refresh token")
	}

	return accessToken, refreshToken, nil
}

// createServiceToken generates a JWT access token for a service client.
//
// Unlike user tokens, service client tokens:
//   - Do not have a refresh token (clients re-authenticate with credentials)
//   - Contain scope claims instead of user claims
//   - Have the client ID as the subject (sub)
//
// Scope resolution:
//   - If service has wildcard (*), grant all requested scopes
//   - If request has wildcard (*), grant all service's scopes
//   - Otherwise, grant intersection of requested and allowed scopes
func (s *AuthServer) createServiceToken(
	ctx context.Context,
	service *model.ServiceClientInternal,
	requestedScopes []string,
) (jwt.AccessToken, *time.Time, []string, error) {
	lg := s.Logger().Derive(log.WithFunction("createServiceTokens"))

	pk, err := s.DB().GetSigningKey(ctx)
	if err != nil {
		lg.Errorf("unable to retrieve signing key: %v", err)
		return "", nil, nil, status.Errorf(
			codes.Internal,
			"unable to retrieve signing key")
	}

	openIDClaims := &jwt.OpenIDClaims{}
	openIDClaims.SetAuthTime(time.Now())

	// Resolve granted scopes based on service permissions and request
	grantedScopes := make([]string, 0, len(requestedScopes))
	if slices.Contains(service.Scopes, "*") {
		// Service has wildcard - grant all requested scopes
		grantedScopes = append(grantedScopes, requestedScopes...)
	} else if slices.Contains(requestedScopes, "*") {
		// Request has wildcard - grant all service's scopes
		grantedScopes = append(grantedScopes, service.Scopes...)
	} else {
		// Grant only the intersection
		for _, s := range requestedScopes {
			if slices.Contains(service.Scopes, s) {
				grantedScopes = append(grantedScopes, s)
			}
		}
	}

	swayriderClaims := jwt.NewSwayRiderServiceClaims(grantedScopes)

	_, accessToken, validUntil, err := jwt.GenerateToken(
		service.ClientID, openIDClaims, swayriderClaims, pk, jwt.DefaultTTL)
	if err != nil {
		lg.Errorf("Unable to generate access token: %v", err)
		return "", nil, nil, status.Errorf(
			codes.Internal,
			"unable to generate access token")
	}

	return accessToken, &validUntil, grantedScopes, nil
}
