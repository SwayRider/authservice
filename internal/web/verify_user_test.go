package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	log "github.com/swayrider/swlib/logger"
)

// TestVerifyUser_GetRendersConfirmPageWithoutDBWork pins the fix for the
// state-changing GET: the GET branch must render the confirmation page
// without touching dbConn at all (a nil dbConn would panic if it were
// dereferenced), leaving the actual verification to the POST that the
// page's inline script auto-submits.
func TestVerifyUser_GetRendersConfirmPageWithoutDBWork(t *testing.T) {
	templates, err := loadTemplates()
	if err != nil {
		t.Fatalf("loadTemplates failed: %v", err)
	}

	handler := verifyUser(nil, templates, log.New())

	req := httptest.NewRequest(http.MethodGet, "/web/verify-user?u=test-user-id&t=test-token", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	body := w.Body.String()
	if !strings.Contains(body, `value="test-user-id"`) {
		t.Error("response body missing hidden u field")
	}
	if !strings.Contains(body, `value="test-token"`) {
		t.Error("response body missing hidden t field")
	}
	if !strings.Contains(body, "verify-user-form") {
		t.Error("response body missing auto-submit form")
	}
}

func TestVerifyUser_MethodNotAllowed(t *testing.T) {
	templates, err := loadTemplates()
	if err != nil {
		t.Fatalf("loadTemplates failed: %v", err)
	}

	handler := verifyUser(nil, templates, log.New())

	req := httptest.NewRequest(http.MethodPut, "/web/verify-user", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}
