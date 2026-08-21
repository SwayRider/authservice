// register.go implements the user registration web handler.
//
// This handler serves the registration form (GET) and processes new user
// sign-ups (POST). It is the target of invite email links and handles the
// full registration flow: invite check → password validation → user creation
// → verification email.
//
// URL: {prefix}/register?email={invitedEmail}

package web

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	passwordvalidator "github.com/wagslane/go-password-validator"
	"github.com/swayrider/authservice/internal/db"
	"github.com/swayrider/authservice/internal/model"
	"github.com/swayrider/authservice/internal/svctoken"
	"github.com/swayrider/grpcclients/mailclient"
	"github.com/swayrider/swlib/crypto"
	log "github.com/swayrider/swlib/logger"
)

// BreachedChecker reports whether a password has appeared in a known data
// breach. It is satisfied structurally by *hibp.Client; kept local to this
// package so the web layer doesn't depend on the server package.
type BreachedChecker interface {
	IsBreached(ctx context.Context, password string) (bool, int, error)
}

// AuditEmitter records security-relevant audit events. Satisfied by
// *server.AuditWriter; kept as an interface so the web layer doesn't depend
// on the server package. Nil disables auditing.
type AuditEmitter interface {
	Emit(ev db.AuditEvent)
}

// RegisterConfig holds configuration for the user registration web handler.
type RegisterConfig struct {
	MailClient       *mailclient.Client
	MailerAddress    string
	RegistrationMode string          // "open" or "invite_only"
	VerifyUserUrl    string          // full base URL for /verify-user, used in verification emails
	Breached         BreachedChecker // password breach detection (nil = off)
	Audit            AuditEmitter    // audit event writer (nil = off)
}

// register returns an HTTP handler for the web registration flow.
//
// GET: renders the registration form with email pre-filled from ?email= query param.
// POST: validates input, creates the user account, consumes the invite (invite_only mode),
// and sends a verification email before rendering the confirmation page.
func register(
	dbConn *db.DB,
	templates *template.Template,
	cfg RegisterConfig,
	l *log.Logger,
) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		lg := l.Derive(
			log.WithComponent("WebServer"),
			log.WithFunction("register"),
		)

		if r.Method == http.MethodGet {
			data := viewData(r)
			if err := templates.ExecuteTemplate(w, "register.html", data); err != nil {
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

		email := r.FormValue("email")
		password := r.FormValue("password")
		confirmPassword := r.FormValue("confirm_password")

		data := viewData(r)
		data["email"] = email

		renderForm := func(errKey string) {
			data["error"] = data["sw_i18n"].(func(string) string)(errKey)
			if err := templates.ExecuteTemplate(w, "register.html", data); err != nil {
				lg.Errorf("failed to execute template: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
			}
		}

		if email == "" {
			renderForm("register_email_required")
			return
		}

		if password != confirmPassword {
			renderForm("register_passwords_no_match")
			return
		}

		if err := passwordvalidator.Validate(password, crypto.PasswordMinEntropy); err != nil {
			renderForm("register_password_too_weak")
			return
		}

		ctx := r.Context()

		if cfg.Breached != nil {
			breached, _, err := cfg.Breached.IsBreached(ctx, password)
			if err != nil {
				lg.Debugf("breach check failed, allowing password (fail open): %v", err)
			} else if breached {
				if cfg.Audit != nil {
					ip, ua := auditClientInfo(r)
					cfg.Audit.Emit(db.AuditEvent{
						EventType: db.AuditPasswordBreachedRejected,
						Email:     email,
						IPAddress: ip,
						UserAgent: ua,
					})
				}
				renderForm("register_password_breached")
				return
			}
		}

		if cfg.RegistrationMode == "invite_only" {
			invited, err := dbConn.IsEmailInvited(ctx, email)
			if err != nil {
				lg.Errorf("failed to check invite for %s: %v", email, err)
				renderForm("register_error")
				return
			}
			if !invited {
				if err := templates.ExecuteTemplate(w, "register-not-invited.html", data); err != nil {
					lg.Errorf("failed to execute template: %v", err)
					w.WriteHeader(http.StatusInternalServerError)
				}
				return
			}
		}

		hashedPassword, err := crypto.CalculatePasswordHash(password)
		if err != nil {
			lg.Errorf("failed to hash password: %v", err)
			renderForm("register_error")
			return
		}

		userId, err := dbConn.RegisterUser(ctx, email, hashedPassword)
		if err != nil {
			if errors.Is(err, db.ErrUniqueViolation) {
				renderForm("register_email_taken")
			} else {
				lg.Errorf("failed to register user %s: %v", email, err)
				renderForm("register_error")
			}
			return
		}

		// Seed the password history with the initial password so a later
		// change cannot rotate back to it. Failures are log-only.
		if err := dbConn.AddToPasswordHistory(ctx, userId, hashedPassword); err != nil {
			lg.Warnf("failed to seed password history for %s: %v", userId, err)
		}

		if cfg.RegistrationMode == "invite_only" {
			if err := dbConn.ConsumeInvite(ctx, email); err != nil {
				lg.Errorf("failed to consume invite for %s: %v", email, err)
			}
		}

		go webSendVerificationEmail(lg, dbConn, cfg.MailClient, cfg.MailerAddress, userId, cfg.VerifyUserUrl)

		if err := templates.ExecuteTemplate(w, "register-pending.html", data); err != nil {
			lg.Errorf("failed to execute template: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}
}

// auditClientInfo extracts the caller IP and user-agent for audit events. The
// web server's middleware chain does not populate source info into the request
// context (unlike the gRPC gateway), so the client IP comes from the
// X-Forwarded-For header set by the gateway/reverse proxy.
func auditClientInfo(r *http.Request) (ip, ua string) {
	return model.FirstIP(r.Header.Get("X-Forwarded-For")), r.UserAgent()
}

// webSendVerificationEmail creates a verification token and sends the verification
// email for a newly web-registered user. Runs in a goroutine; errors are only logged.
func webSendVerificationEmail(
	lg *log.Logger,
	dbConn *db.DB,
	mailClient *mailclient.Client,
	mailerAddress string,
	userId string,
	verifyUserUrl string,
) {
	ctx := context.Background()

	user, err := dbConn.GetUserByID(ctx, userId)
	if err != nil || user == nil {
		lg.Errorf("user %s not found after registration: %v", userId, err)
		return
	}

	token, err := dbConn.CreateVerificationToken(ctx, &user.User)
	if err != nil {
		lg.Errorf("failed to create verification token for %s: %v", userId, err)
		return
	}

	sep := "?"
	if strings.Contains(verifyUserUrl, "?") {
		sep = "&"
	}
	fullVerifyUrl := fmt.Sprintf("%s%su=%s&t=%s",
		verifyUserUrl, sep,
		url.QueryEscape(userId),
		url.QueryEscape(token.Token))

	svcToken, err := svctoken.MailSendToken(ctx, dbConn)
	if err != nil {
		lg.Errorf("failed to mint mail service token: %v", err)
		return
	}

	_, err = mailClient.SendTemplate(
		svcToken,
		mailclient.NewTemplateMail(
			mailerAddress, []string{user.Email}, nil, nil,
			"SwayRider - Confirm Email",
			"verify_user.html", "verify_user.txt",
			map[string]string{
				"Email":           user.Email,
				"VerificationURL": fullVerifyUrl,
				"Year":            fmt.Sprintf("%d", time.Now().Year()),
			}))
	if err != nil {
		lg.Errorf("failed to send verification email to %s: %v", user.Email, err)
	}
}
