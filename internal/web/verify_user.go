// verify_user.go implements the email verification web handler.
//
// This handler serves a confirmation page (GET) and processes the actual
// verification (POST). It mirrors the reset_password.go pattern: the emailed
// link only ever triggers a GET, which renders a page that auto-submits a
// POST via inline JS, so a real user clicking the link still lands on the
// success page in one hop while the state-changing request itself is a POST
// (not a bare GET, which is CSRF-shaped and vulnerable to link-prefetching
// email scanners silently consuming the token).

package web

import (
	"html/template"
	"net/http"
	"github.com/swayrider/authservice/internal/db"
	"github.com/swayrider/swlib/jwt"
	log "github.com/swayrider/swlib/logger"
)

// verifyUser returns an HTTP handler for the email verification flow.
//
// GET: Renders the confirmation page with u and t preserved as hidden fields. Does no DB work.
// POST: Validates the token, marks the user verified, and renders the completion page.
//
// URL parameters:
//   - u: User ID
//   - t: Verification token
func verifyUser(
	dbConn *db.DB,
	templates *template.Template,
	l *log.Logger,
) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		lg := l.Derive(
			log.WithComponent("WebServer"),
			log.WithFunction("verifyUser"),
		)

		if r.Method == http.MethodGet {
			data := viewData(r)
			if err := templates.ExecuteTemplate(w, "verify-user-confirm.html", data); err != nil {
				lg.Errorf("failed to execute template: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
			}
			return
		}

		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		data := viewData(r)
		userId := r.FormValue("u")
		if userId == "" {
			lg.Warnln("no user id")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		data["u"] = userId
		token := r.FormValue("t")
		if token == "" {
			lg.Warnln("no token")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		data["t"] = token

		ctx := r.Context()

		user, err := dbConn.GetUserByID(ctx, userId)
		if err != nil {
			lg.Errorf("user %s not found: %v", userId, err)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if !user.IsVerified {
			tkn, err := dbConn.GetVerificationToken(ctx, &user.User)
			if err != nil {
				lg.Warnf("failed to retrieve verification token: %v", err)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if !tkn.IsNotExpired() {
				lg.Warnf("Verification token for user %s expired", userId)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if !tkn.Verify(userId, token) {
				lg.Warnf("Verification token for user %s invalid", userId)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			err = dbConn.MarkUserVerified(ctx, userId)
			if err != nil {
				lg.Errorf("failed to mark user %s as verified: %v", userId, err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			if err = dbConn.DeleteVerificationToken(ctx, userId); err != nil {
				lg.Warnf("failed to delete verification token: %v", err)
			}
		}

		data["sw_isEmailVerified"] = func(*jwt.Claims) bool {
			return true
		}
		
		if err := templates.ExecuteTemplate(w, "registration-complete.html", data); err != nil {
			lg.Errorf("failed to execute template: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}
}
