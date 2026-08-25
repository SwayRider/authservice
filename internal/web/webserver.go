// Package web provides a static web server for email verification pages.
//
// The web server serves HTML templates for:
//   - Email verification completion (after clicking verification link)
//   - Registration success pages
//
// These pages are shown to users after clicking email links and provide
// feedback on the verification status with deep links back to the mobile app.

package web

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"github.com/swayrider/authservice/internal/db"
	"github.com/swayrider/swlib/http/cookies"
	"github.com/swayrider/swlib/jwt"
	"github.com/swayrider/swlib/security"
	log "github.com/swayrider/swlib/logger"
	"github.com/swayrider/swlib/totp"
)

// registerEndpointProfiles marks the web server's pages as publicly
// accessible (or unverified-only) so the Auth middleware wrapping the mux
// lets them through. The profiles must follow the configured prefix — the
// paths are matched against the request path, so hardcoding /web here would
// 401 every page as soon as WEB_PATH_PREFIX changes.
func registerEndpointProfiles(prefix string) {
	trimmed := strings.TrimRight(prefix, "/")
	security.PublicEndpoint(prefix)
	if trimmed != "" {
		security.PublicEndpoint(trimmed)
	}
	security.PublicEndpoint(prefix + "index.html")

	security.PublicEndpoint(prefix + "verify-user")
	security.PublicEndpoint(prefix + "reset-password")
	security.PublicEndpoint(prefix + "reset-mfa")
	security.PublicEndpoint(prefix + "register")

	security.UnverifiedEndpoint(prefix + "registration-complete")
}

//go:embed templates
var webFS embed.FS

// WebServer wraps an HTTP server for serving static verification pages.
type WebServer struct {
	http *http.Server // Underlying HTTP server
}

// Server returns the underlying HTTP server.
func (s WebServer) Server() *http.Server {
	return s.http
}

// New creates a new WebServer with the configured routes.
// Routes:
//   - {prefix}/verify-user: Email verification endpoint
//   - {prefix}/reset-password: Password reset form
//   - {prefix}/register: User registration form (only if cfg != nil)
//   - {prefix}/registration-complete: Post-verification success page
//   - {prefix}/: Index page
func New(
	addr string,
	prefix string,
	dbConn *db.DB,
	l *log.Logger,
	cfg *RegisterConfig,
) *WebServer {
	lg := l.Derive(
		log.WithComponent("WebServer"),
		log.WithFunction("New"),
	)
	templates, err := loadTemplates()
	if err != nil {
		return nil
	}

	if prefix == "" {
		prefix = "/"
	} else if prefix[len(prefix)-1] != '/' {
		prefix += "/"
	}

	registerEndpointProfiles(prefix)

	// Guard against a silent 401 regression: these pages must be open to
	// anonymous visitors (the emailed reset/verification links are opened
	// while logged out). If any is missing from the public profile -- e.g.
	// the WEB_PATH_PREFIX it was registered under doesn't match the prefix
	// the mux is mounted on -- middlewares.Auth will hard-401 every GET.
	for _, ep := range []string{
		prefix + "verify-user",
		prefix + "reset-password",
		prefix + "reset-mfa",
		prefix + "register",
	} {
		if !security.GetEndpointProfileForMethod(ep, http.MethodGet).AllowPublic {
			lg.Errorf("web endpoint %s is NOT registered as public; anonymous GET will return 401 unauthorized", ep)
		}
	}
	lg.Infof("web server mounted on prefix %q (public pages: verify-user, reset-password, reset-mfa, register)", prefix)

	mux := http.NewServeMux()
	mux.HandleFunc(
		fmt.Sprintf("%s%s", prefix, "verify-user"),
		verifyUser(dbConn, templates, lg),
	)
	var breached BreachedChecker
	var audit AuditEmitter
	var mfaTotp totp.Config
	var mfaBackupCodeCount int
	var mfaResetMaxPasswordAttempts int
	if cfg != nil {
		breached = cfg.Breached
		audit = cfg.Audit
		mfaTotp = cfg.MFATotp
		mfaBackupCodeCount = cfg.MFABackupCodeCount
		mfaResetMaxPasswordAttempts = cfg.MFAResetMaxPasswordAttempts
	}
	mux.HandleFunc(
		fmt.Sprintf("%s%s", prefix, "reset-password"),
		resetPassword(dbConn, templates, breached, audit, lg),
	)
	mux.HandleFunc(
		fmt.Sprintf("%s%s", prefix, "reset-mfa"),
		resetMfa(dbConn, templates, mfaTotp, mfaBackupCodeCount, mfaResetMaxPasswordAttempts, audit, lg),
	)
	if cfg != nil {
		mux.HandleFunc(
			fmt.Sprintf("%s%s", prefix, "register"),
			register(dbConn, templates, *cfg, lg),
		)
	}
	mux.HandleFunc(
		fmt.Sprintf("%s%s", prefix, "registration-complete"),
		func(w http.ResponseWriter, r *http.Request) {
			data := viewData(r)
			if err := templates.ExecuteTemplate(w, "registration-complete.html", data); err != nil {
				lg.Derive(log.WithFunction("RegstrationCompleteHandler")).Errorf("%v", err)
			}
		},
	)
	mux.HandleFunc(
		prefix,
		func(w http.ResponseWriter, r *http.Request) {
			data := viewData(r)
			if err := templates.ExecuteTemplate(w, "index.html", data); err != nil {
				lg.Derive(log.WithFunction("IndexHandler")).Errorf("%v", err)
			}
		},
	)

	return &WebServer{
		http: &http.Server{
			Addr:    addr,
			Handler: withOptionalClaims(publicKeysFn(dbConn), lg)(mux),
		},
	}
}

// withOptionalClaims extracts JWT claims (if a valid token is present) and
// stores them in the request context, but NEVER rejects a request.
//
// The web server serves only public email-verification pages (verify-user,
// reset-password, reset-mfa, register). Anonymous visitors -- exactly the
// people clicking an emailed reset/verification link -- must always be
// admitted. Wrapping the mux in middlewares.Auth (which hard-401s any
// non-public path when no valid token is presented) is what produced the
// "401 unauthorized" for logged-out users opening the MFA-reset link: a
// forgotten PublicEndpoint registration or a WEB_PATH_PREFIX mismatch between
// authservice and the gateway was enough to lock them out. Here we keep the
// logged-in rendering (sw_userClaims) for users who happen to be signed in,
// while guaranteeing the pages are reachable for everyone.
func withOptionalClaims(
	publicKeysFn security.PublicKeysFn,
	l *log.Logger,
) func(http.Handler) http.Handler {
	lg := l.Derive(
		log.WithComponent("WebServer"),
		log.WithFunction("withOptionalClaims"),
	)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			var tokenStr string
			if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
				tokenStr = strings.TrimPrefix(auth, "Bearer ")
			} else if cookie, err := r.Cookie(cookies.FullCookieName("access_token")); err == nil {
				if b, derr := cookies.DecodeValue(cookie); derr == nil {
					tokenStr = string(b)
				}
			}

			if tokenStr != "" {
				if keys, kerr := publicKeysFn(); kerr == nil {
					for _, k := range keys {
						claims, verr := jwt.VerifyToken(tokenStr, k, jwt.VerifyDefault)
						if verr == nil && claims != nil {
							ctx = context.WithValue(ctx, security.ClaimsKey, claims)
							ctx = context.WithValue(ctx, security.JwtKey, tokenStr)
							break
						}
					}
				} else {
					lg.Debugf("withOptionalClaims: failed to load public keys: %v", kerr)
				}
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// Start begins listening for HTTP requests in a background goroutine.
func (s *WebServer) Start() error {
	if s == nil {
		return errors.New("webserver initialization error")
	}
	go func() {
		err := s.http.ListenAndServe()
		if err != nil {
			if err != http.ErrServerClosed {
				panic(err)
			}
		}
	}()
	return nil
}

// Shutdown gracefully stops the HTTP server with a 5-second timeout.
func (s *WebServer) Shutdown(ctx context.Context) error {
	shudownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return s.http.Shutdown(shudownCtx)
}

// loadTemplates loads all HTML templates from the embedded filesystem.
func loadTemplates() (*template.Template, error) {
	tmplFS, err := fs.Sub(webFS, "templates")
	if err != nil {
		return nil, err
	}

	return template.ParseFS(
		tmplFS,
		"*.html",
	)
}

// publicKeysFn returns a function that retrieves JWT public keys for token verification.
func publicKeysFn(dbConn *db.DB) security.PublicKeysFn {
	return func() ([]string, error) {
		ctx := context.Background()
		keys, err := dbConn.GetVerificationKeys(ctx)
		if err != nil {
			return nil, err
		}
		return keys, nil
	}
}
