// verify_user.go implements the email verification web handler.
//
// This handler processes verification links clicked from email. It validates
// the token, marks the user as verified, and displays a success page.

package web

import (
	"html/template"
	"net/http"
	"github.com/swayrider/authservice/internal/db"
	"github.com/swayrider/swlib/jwt"
	log "github.com/swayrider/swlib/logger"
)

// verifyUser returns an HTTP handler that processes email verification requests.
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

		data := viewData(r)
		userIdIface, ok := data["u"]
		if !ok {
			lg.Warnln("no user id")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		userId := userIdIface.(string)
		tokenIface, ok := data["t"]
		if !ok {
			lg.Warnln("no token")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		token := tokenIface.(string)

		ctx := r.Context()

		user, err := dbConn.GetUserByID(ctx, userId)
		if err != nil {
			lg.Errorf("user %s not found: %v", userId, err)
			w.WriteHeader(http.StatusNotFound)
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
