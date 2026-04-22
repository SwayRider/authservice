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
//   - LoginResponse/RefreshResponse: Sets the cookie with the new refresh token
//   - LogoutResponse: Clears the cookie
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
	case *authv1.LogoutResponse:
		unsetCookie = true
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

// CookieHeaderMatcher is a grpc-gateway header matcher that forwards cookie headers.
// This allows the refresh token to be read from cookies in addition to the request body.
func CookieHeaderMatcher(header string) (string, bool) {
	if strings.EqualFold(header, "cookie") {
		return "cookie", true
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

	u, err := s.DB().GetUserByEmail(ctx, req.Email)
	if err != nil {
		lg.Debugf("user %s failed a login attempt: %v", req.Email, err)
		if errors.Is(err, db.ErrUserNotFound) {
			return nil, status.Error(
				codes.Unauthenticated,
				"invalid email or password")
		}
	}

	if !u.PasswordHash.Valid {
		lg.Debugf("user %s failed a login attempt: invalid password", req.Email)
		return nil, status.Error(
			codes.Unauthenticated,
			"invalid email or password")
	}

	var passwordOk bool
	passwordOk, err = crypto.VerifyPassword(u.PasswordHash.String, req.Password)
	if err != nil {
		lg.Debugf("user %s failed a login attempt: %v", req.Email, err)
		return nil, status.Error(
			codes.Unauthenticated,
			"invalid email or password")
	}
	if !passwordOk {
		lg.Debugf("user %s failed a login attempt: invalid password", req.Email)
		return nil, status.Error(
			codes.Unauthenticated,
			"invalid email or password")
	}

	origIp, _ := security.GetOrigIp(ctx)
	userAgent, _ := security.GetUserAgent(ctx)
	accessToken, refreshToken, err := s.createAuthTokens(ctx, u, origIp, userAgent)
	if err != nil {
		return nil, err
	}

	grpc.SetHeader(ctx, metadata.Pairs(
		"remember-me", fmt.Sprintf("%v", req.RememberMe)))

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

	clnt, err := s.DB().GetServiceClientByID(ctx, req.ClientId)
	if err != nil {
		lg.Debugf("service client %s not found: %v", req.ClientId, err)
		if errors.Is(err, db.ErrServiceClientNotFound) {
			return nil, status.Error(
				codes.NotFound,
				"service client not found")
		}
	}

	if !clnt.ClientSecretHash.Valid {
		lg.Debugf("service client %s not found: invalid secret", req.ClientId)
		return nil, status.Error(
			codes.Unauthenticated,
			"service client authentication error")
	}

	// Verify client secret using Argon2id
	var secretOk bool
	secretOk, err = crypto.VerifyPassword(clnt.ClientSecretHash.String, req.ClientSecret)
	if err != nil {
		lg.Debugf("service client %s authentication error: %v", req.ClientId, err)
		return nil, status.Error(
			codes.Unauthenticated,
			"service client authentication error")
	}
	if !secretOk {
		lg.Debugf("service client %s authentication error: invalid secret", req.ClientId)
		return nil, status.Error(
			codes.Unauthenticated,
			"service client authentication error")
	}

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
//   - Token must be bound to the same IP and user agent (prevents token theft)
//   - Old token is deleted before new tokens are issued
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
	refreshToken, _ := security.GetRefreshToken(ctx)
	if refreshToken == "" {
		refreshToken = req.RefreshToken
	}

	// Retrieve and validate the refresh token
	token, err := s.DB().GetRefreshToken(ctx, refreshToken)
	if err != nil {
		lg.Errorf("could not get refresh token: %v", err)
		return nil, status.Errorf(
			codes.Unauthenticated,
			"could not get refresh token")
	}

	// Verify token binding (IP and user agent)
	err = token.Verify(origIp, userAgent)
	if err != nil {
		lg.Errorf("could not verify refresh token: %v", err)
		return nil, status.Errorf(
			codes.Unauthenticated,
			"could not verify refresh token")
	}

	// Invalidate the old refresh token (rotation)
	err = s.DB().DeleteRefreshToken(ctx, req.RefreshToken)
	if err != nil {
		lg.Warnf("could not delete refresh token: %v", err)
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
