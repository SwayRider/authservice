// reset_mfa.go implements the email-verified MFA/TOTP reset web handler --
// the confirmation half of the flow started by AuthServer.RequestMfaReset
// (internal/server/mfa_reset.go).
//
// Unlike reset_password.go/verify_user.go, GET here does real (read-only)
// database work: it needs the token row's pending secret to render the QR
// code and manual key. That's still safe against link-prefetch scanners --
// GET never mutates state, only POST does (replacing the active secret and
// issuing new backup codes), mirroring the CSRF-shaped-GET protection those
// two handlers use.
//
// URL: {prefix}/reset-mfa?u={userId}&t={token}

package web

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"strings"
	"time"

	qrcode "github.com/yeqown/go-qrcode/v2"
	"github.com/yeqown/go-qrcode/writer/standard"

	"github.com/swayrider/authservice/internal/db"
	"github.com/swayrider/swlib/crypto"
	log "github.com/swayrider/swlib/logger"
	"github.com/swayrider/swlib/totp"
)

const (
	// mfaResetBackupCodeLength mirrors internal/server/mfa.go's
	// mfaBackupCodeLength -- kept local so this package doesn't depend on
	// the server package (same reasoning as BreachedChecker/AuditEmitter).
	mfaResetBackupCodeLength = 8

	mfaResetQRBlockWidth = 6
	mfaResetQRBorder     = 12
)

// nopWriteCloser adapts a plain io.Writer to the io.WriteCloser the QR
// writer expects.
type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }

// renderMFAResetQRPNG mirrors internal/server/mfa.go's renderQRPNG.
func renderMFAResetQRPNG(otpauthURL string) ([]byte, error) {
	qrc, err := qrcode.NewWith(otpauthURL,
		qrcode.WithErrorCorrectionLevel(qrcode.ErrorCorrectionMedium))
	if err != nil {
		return nil, fmt.Errorf("failed to create QR code: %w", err)
	}
	var buf bytes.Buffer
	w := standard.NewWithWriter(nopWriteCloser{&buf},
		standard.WithBuiltinImageEncoder(standard.PNG_FORMAT),
		standard.WithQRWidth(mfaResetQRBlockWidth),
		standard.WithBorderWidth(mfaResetQRBorder))
	if err := qrc.Save(w); err != nil {
		return nil, fmt.Errorf("failed to render QR code: %w", err)
	}
	return buf.Bytes(), nil
}

// formatSecretKey groups a base32 secret into 4-character blocks for
// display, e.g. "ABCD EFGH IJKL".
func formatSecretKey(secret string) string {
	upper := strings.ToUpper(strings.ReplaceAll(secret, " ", ""))
	var b strings.Builder
	for i, r := range upper {
		if i > 0 && i%4 == 0 {
			b.WriteByte(' ')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// generateBackupCodesForReset generates a fresh backup-code set, hashes each
// code with Argon2id, and replaces the stored set for userID. Mirrors
// internal/server/mfa.go's generateAndStoreBackupCodes; duplicated locally
// so this package doesn't depend on the server package.
func generateBackupCodesForReset(ctx context.Context, dbConn *db.DB, userID string, count int) ([]string, error) {
	codes, err := totp.GenerateBackupCodes(count, mfaResetBackupCodeLength)
	if err != nil {
		return nil, err
	}
	hashes := make([]string, 0, len(codes))
	for _, code := range codes {
		h, err := crypto.CalculatePasswordHash(code)
		if err != nil {
			return nil, err
		}
		hashes = append(hashes, h)
	}
	if err := dbConn.StoreBackupCodeHashes(ctx, userID, hashes); err != nil {
		return nil, err
	}
	return codes, nil
}

// resetMfa returns an HTTP handler for the email-verified MFA reset flow.
//
// Extra safety check: the emailed link's token alone is not treated as
// sufficient proof of identity -- the account password must be re-verified
// on this page before the QR code/secret is ever revealed. This protects
// against the link itself leaking or being reused by someone who isn't the
// account owner (a compromised or shared inbox, shoulder-surfing, etc.).
//
// GET/POST: while the token's password_verified flag is false, only a
// password prompt is shown; a correct password flips the flag and reveals
// the QR/manual key + code-confirmation form (below). Wrong passwords
// increment a per-token attempt counter; exceeding the limit deletes the
// token, mirroring mfa_challenges.attempts for login MFA challenges.
//
// GET/POST (once password_verified): validates the token, renders a
// QR/manual key for the pending secret, plus a code-confirmation form.
// POST with a code checks it against the pending secret, and on success
// atomically replaces the active secret and issues a fresh backup-code set
// (shown once on the completion page).
func resetMfa(
	dbConn *db.DB,
	templates *template.Template,
	totpCfg totp.Config,
	backupCodeCount int,
	maxPasswordAttempts int,
	audit AuditEmitter,
	l *log.Logger,
) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		lg := l.Derive(
			log.WithComponent("WebServer"),
			log.WithFunction("resetMfa"),
		)
		ctx := r.Context()

		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		userId := r.URL.Query().Get("u")
		token := r.URL.Query().Get("t")
		if r.Method == http.MethodPost {
			if err := r.ParseForm(); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			userId = r.FormValue("u")
			token = r.FormValue("t")
		}

		data := viewData(r)
		data["u"] = userId
		data["t"] = token

		renderInvalidLink := func() {
			data["error"] = data["sw_i18n"].(func(string) string)("reset_mfa_invalid_link")
			if err := templates.ExecuteTemplate(w, "reset-mfa.html", data); err != nil {
				lg.Errorf("failed to execute template: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
			}
		}

		if userId == "" || token == "" {
			renderInvalidLink()
			return
		}

		resetToken, err := dbConn.GetMFAResetToken(ctx, userId)
		if err != nil {
			lg.Warnf("failed to retrieve MFA reset token for user %s: %v", userId, err)
			renderInvalidLink()
			return
		}
		if !resetToken.Verify(userId, token) {
			lg.Warnf("MFA reset token for user %s does not match or is expired", userId)
			renderInvalidLink()
			return
		}

		user, err := dbConn.GetUserByID(ctx, userId)
		if err != nil || user == nil {
			lg.Warnf("user not found: %s: %v", userId, err)
			renderInvalidLink()
			return
		}

		renderPasswordPrompt := func(errKey string) {
			if errKey != "" {
				data["error"] = data["sw_i18n"].(func(string) string)(errKey)
			}
			if err := templates.ExecuteTemplate(w, "reset-mfa-password.html", data); err != nil {
				lg.Errorf("failed to execute template: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
			}
		}

		otpauthURL := totp.GenerateOTPAuthURL(resetToken.PendingSecret, user.Email, "SwayRider")

		renderForm := func(errKey string) {
			png, pngErr := renderMFAResetQRPNG(otpauthURL)
			if pngErr != nil {
				lg.Errorf("failed to render QR code: %v", pngErr)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			data["qrPngBase64"] = base64.StdEncoding.EncodeToString(png)
			data["manualKey"] = formatSecretKey(resetToken.PendingSecret)
			if errKey != "" {
				data["error"] = data["sw_i18n"].(func(string) string)(errKey)
			}
			if err := templates.ExecuteTemplate(w, "reset-mfa.html", data); err != nil {
				lg.Errorf("failed to execute template: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
			}
		}

		if !resetToken.PasswordVerified {
			if r.Method == http.MethodGet {
				renderPasswordPrompt("")
				return
			}

			password := r.FormValue("password")
			passwordOk, verr := crypto.VerifyPassword(user.PasswordHash.String, password)
			if verr != nil || !passwordOk || !user.PasswordHash.Valid {
				attempts, aerr := dbConn.IncrementMFAResetAttempts(ctx, userId)
				if aerr != nil {
					lg.Warnf("failed to record MFA reset attempt for user %s: %v", userId, aerr)
				}
				if maxPasswordAttempts > 0 && attempts >= maxPasswordAttempts {
					if derr := dbConn.DeleteMFAResetToken(ctx, userId); derr != nil {
						lg.Warnf("failed to delete MFA reset token for user %s: %v", userId, derr)
					}
					renderInvalidLink()
					return
				}
				renderPasswordPrompt("reset_mfa_password_invalid")
				return
			}

			if err := dbConn.MarkMFAResetPasswordVerified(ctx, userId); err != nil {
				lg.Errorf("failed to mark MFA reset password verified for user %s: %v", userId, err)
				renderPasswordPrompt("reset_mfa_error")
				return
			}

			renderForm("")
			return
		}

		if r.Method == http.MethodGet {
			renderForm("")
			return
		}

		code := r.FormValue("code")
		valid, err := totp.Validate(resetToken.PendingSecret, code, time.Now(), totpCfg)
		if err != nil || !valid {
			renderForm("reset_mfa_invalid_code")
			return
		}

		if err := dbConn.ReplaceMFASecret(ctx, userId, resetToken.PendingSecret); err != nil {
			lg.Errorf("failed to replace MFA secret for user %s: %v", userId, err)
			renderForm("reset_mfa_error")
			return
		}

		codes, err := generateBackupCodesForReset(ctx, dbConn, userId, backupCodeCount)
		if err != nil {
			lg.Errorf("failed to generate backup codes for user %s: %v", userId, err)
			renderForm("reset_mfa_error")
			return
		}

		if err := dbConn.DeleteMFAResetToken(ctx, userId); err != nil {
			lg.Warnf("failed to delete MFA reset token for user %s: %v", userId, err)
		}

		if audit != nil {
			ip, ua := auditClientInfo(r)
			audit.Emit(db.AuditEvent{
				EventType: db.AuditMFAReset,
				UserID:    &userId,
				Email:     user.Email,
				IPAddress: ip,
				UserAgent: ua,
			})
		}

		data["backupCodes"] = codes
		if err := templates.ExecuteTemplate(w, "reset-mfa-complete.html", data); err != nil {
			lg.Errorf("failed to execute template: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}
}
