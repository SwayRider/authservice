package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	log "github.com/swayrider/swlib/logger"
	"github.com/swayrider/swlib/totp"
)

// TestResetMfa_MethodNotAllowed mirrors verify_user_test.go's coverage of
// the shared method-guard, which runs before any database work.
func TestResetMfa_MethodNotAllowed(t *testing.T) {
	templates, err := loadTemplates()
	if err != nil {
		t.Fatalf("loadTemplates failed: %v", err)
	}

	handler := resetMfa(nil, templates, totp.Config{}, 10, 5, nil, log.New())

	req := httptest.NewRequest(http.MethodPut, "/web/reset-mfa", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

// TestResetMfa_MissingParams_RendersInvalidLinkWithoutDBWork pins that a
// request missing u/t is rejected before dbConn is ever touched -- a nil
// dbConn would panic if it were dereferenced, so this also guards against a
// future change accidentally moving a DB call ahead of the param check.
//
// The password-gate/QR/code-confirmation logic all requires a real *db.DB
// (GetMFAResetToken, GetUserByID, ...) and isn't unit-testable without one --
// internal/web handlers take the concrete *db.DB type rather than an
// interface, the same limitation reset_password.go/verify_user.go already
// have (neither has coverage for their DB-dependent branches either).
func TestResetMfa_MissingParams_RendersInvalidLinkWithoutDBWork(t *testing.T) {
	templates, err := loadTemplates()
	if err != nil {
		t.Fatalf("loadTemplates failed: %v", err)
	}

	handler := resetMfa(nil, templates, totp.Config{}, 10, 5, nil, log.New())

	req := httptest.NewRequest(http.MethodGet, "/web/reset-mfa", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (form re-render)", w.Code, http.StatusOK)
	}
	body := w.Body.String()
	if !strings.Contains(body, "invalid or has expired") {
		t.Errorf("response body missing invalid-link message: %s", body)
	}
}
