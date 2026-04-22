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
	"time"

	"github.com/swayrider/authservice/internal/db"
	"github.com/swayrider/swlib/http/middlewares"
	"github.com/swayrider/swlib/security"
	log "github.com/swayrider/swlib/logger"
)

func init() {
	security.PublicEndpoint("/web")
	security.PublicEndpoint("/web/")
	security.PublicEndpoint("/web/index.html")

	security.PublicEndpoint("/web/verify-user")
	security.PublicEndpoint("/web/reset-password")

	security.UnverifiedEndpoint("/web/registration-complete")
}

//go:embed templates
var webFS embed.FS

// WebServer wraps an HTTP server for serving static verification pages.
type WebServer struct {
	prefix string       // URL path prefix for all routes
	http   *http.Server // Underlying HTTP server
}

// Server returns the underlying HTTP server.
func (s WebServer) Server() *http.Server {
	return s.http
}

// New creates a new WebServer with the configured routes.
// Routes:
//   - {prefix}/verify-user: Email verification endpoint
//   - {prefix}/registration-complete: Post-registration success page
//   - {prefix}/: Index page
func New(
	addr string,
	prefix string,
	dbConn *db.DB,
	l *log.Logger,
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

	mux := http.NewServeMux()
	mux.HandleFunc(
		fmt.Sprintf("%s%s", prefix, "verify-user"),
		verifyUser(dbConn, templates, lg),
	)
	mux.HandleFunc(
		fmt.Sprintf("%s%s", prefix, "reset-password"),
		resetPassword(dbConn, templates, lg),
	)
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
			Handler: middlewares.Auth(
				mux, publicKeysFn(dbConn), lg),
		},
	}
}

// Start begins listening for HTTP requests in a background goroutine.
func (s *WebServer) Start() error {
	if s == nil {
		return errors.New("Webserver initialization error")
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
