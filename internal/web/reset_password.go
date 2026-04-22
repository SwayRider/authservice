// reset_password.go implements the password reset web handler.
//
// This handler serves the password reset form (GET) and processes the
// new password submission (POST). It mirrors the verify_user.go pattern
// but requires user input for the new password.
//
// URL: {prefix}/reset-password?u={userId}&t={token}

package web

import (
	"html/template"
	"net/http"

	passwordvalidator "github.com/wagslane/go-password-validator"
	"github.com/swayrider/authservice/internal/db"
	"github.com/swayrider/swlib/crypto"
	log "github.com/swayrider/swlib/logger"
)

// resetPassword returns an HTTP handler for the password reset flow.
//
// GET: Renders the password entry form with u and t preserved as hidden fields.
// POST: Validates the token, hashes the new password, stores it, and renders the completion page.
func resetPassword(
	dbConn *db.DB,
	templates *template.Template,
	l *log.Logger,
) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		lg := l.Derive(
			log.WithComponent("WebServer"),
			log.WithFunction("resetPassword"),
		)

		if r.Method == http.MethodGet {
			data := viewData(r)
			if err := templates.ExecuteTemplate(w, "reset-password.html", data); err != nil {
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

		userId := r.FormValue("u")
		token := r.FormValue("t")
		newPassword := r.FormValue("new_password")
		confirmPassword := r.FormValue("confirm_password")

		// Build base template data (includes lang, i18n, etc.)
		data := viewData(r)
		data["u"] = userId
		data["t"] = token

		renderForm := func(errKey string) {
			data["error"] = data["sw_i18n"].(func(string) string)(errKey)
			if err := templates.ExecuteTemplate(w, "reset-password.html", data); err != nil {
				lg.Errorf("failed to execute template: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
			}
		}

		if userId == "" || token == "" {
			renderForm("reset_password_invalid_link")
			return
		}

		if newPassword != confirmPassword {
			renderForm("reset_password_passwords_no_match")
			return
		}

		if err := passwordvalidator.Validate(newPassword, crypto.PasswordMinEntropy); err != nil {
			renderForm("reset_password_error")
			return
		}

		ctx := r.Context()

		user, err := dbConn.GetUserByID(ctx, userId)
		if err != nil || user == nil {
			lg.Warnf("user not found: %s: %v", userId, err)
			renderForm("reset_password_invalid_link")
			return
		}

		resetToken, err := dbConn.GetResetPasswordToken(ctx, &user.User)
		if err != nil {
			lg.Warnf("failed to retrieve reset token for user %s: %v", userId, err)
			renderForm("reset_password_invalid_link")
			return
		}

		if !resetToken.IsNotExpired() {
			lg.Warnf("reset token for user %s is expired", userId)
			renderForm("reset_password_invalid_link")
			return
		}

		if !resetToken.Verify(userId, token) {
			lg.Warnf("reset token for user %s does not match", userId)
			renderForm("reset_password_invalid_link")
			return
		}

		hashedPassword, err := crypto.CalculatePasswordHash(newPassword)
		if err != nil {
			lg.Errorf("failed to hash password for user %s: %v", userId, err)
			renderForm("reset_password_error")
			return
		}

		if err := dbConn.UpdatePassword(ctx, user.ID, hashedPassword); err != nil {
			lg.Errorf("failed to update password for user %s: %v", userId, err)
			renderForm("reset_password_error")
			return
		}

		if err := dbConn.DeleteResetPasswordToken(ctx, user.ID); err != nil {
			lg.Warnf("failed to delete reset token for user %s: %v", userId, err)
		}

		if err := templates.ExecuteTemplate(w, "reset-password-complete.html", data); err != nil {
			lg.Errorf("failed to execute template: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}
}
