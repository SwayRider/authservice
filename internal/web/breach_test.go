package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/swayrider/authservice/internal/db"
	log "github.com/swayrider/swlib/logger"
)

// stubBreachedChecker implements BreachedChecker with fixed results.
type stubBreachedChecker struct {
	breached bool
}

func (s *stubBreachedChecker) IsBreached(_ context.Context, _ string) (bool, int, error) {
	return s.breached, 0, nil
}

// stubAuditEmitter implements AuditEmitter, recording emitted events.
type stubAuditEmitter struct {
	events []db.AuditEvent
}

func (s *stubAuditEmitter) Emit(ev db.AuditEvent) {
	s.events = append(s.events, ev)
}

// strongTestPassword passes the entropy validator used by both web handlers.
const strongTestPassword = "TestP@ssw0rd!SecureEnough"

// postForm builds a POST request with a url-encoded form body.
func postForm(t *testing.T, path string, form url.Values) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func TestRegister_BreachedPassword_RendersBreachError(t *testing.T) {
	templates, err := loadTemplates()
	if err != nil {
		t.Fatalf("loadTemplates failed: %v", err)
	}

	audit := &stubAuditEmitter{}
	cfg := RegisterConfig{
		Breached: &stubBreachedChecker{breached: true},
		Audit:    audit,
	}
	handler := register(nil, templates, cfg, log.New())

	form := url.Values{
		"email":            {"new@example.com"},
		"password":         {strongTestPassword},
		"confirm_password": {strongTestPassword},
	}
	w := httptest.NewRecorder()
	handler(w, postForm(t, "/web/register", form))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (form re-render)", w.Code, http.StatusOK)
	}
	body := w.Body.String()
	if !strings.Contains(body, "This password has appeared in a known data breach") {
		t.Errorf("response body missing breached-password message: %s", body)
	}

	if len(audit.events) != 1 {
		t.Fatalf("emitted %d audit events, want 1", len(audit.events))
	}
	ev := audit.events[0]
	if ev.EventType != db.AuditPasswordBreachedRejected {
		t.Errorf("event type = %s, want %s", ev.EventType, db.AuditPasswordBreachedRejected)
	}
	if ev.Email != "new@example.com" {
		t.Errorf("event email = %q, want %q", ev.Email, "new@example.com")
	}
}

func TestResetPassword_BreachedPassword_RendersBreachError(t *testing.T) {
	templates, err := loadTemplates()
	if err != nil {
		t.Fatalf("loadTemplates failed: %v", err)
	}

	audit := &stubAuditEmitter{}
	handler := resetPassword(nil, templates, &stubBreachedChecker{breached: true}, audit, log.New())

	form := url.Values{
		"u":                {"test-user-id"},
		"t":                {"test-token"},
		"new_password":     {strongTestPassword},
		"confirm_password": {strongTestPassword},
	}
	w := httptest.NewRecorder()
	handler(w, postForm(t, "/web/reset-password", form))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (form re-render)", w.Code, http.StatusOK)
	}
	body := w.Body.String()
	if !strings.Contains(body, "This password has appeared in a known data breach") {
		t.Errorf("response body missing breached-password message: %s", body)
	}

	if len(audit.events) != 1 {
		t.Fatalf("emitted %d audit events, want 1", len(audit.events))
	}
	ev := audit.events[0]
	if ev.EventType != db.AuditPasswordBreachedRejected {
		t.Errorf("event type = %s, want %s", ev.EventType, db.AuditPasswordBreachedRejected)
	}
	if ev.UserID == nil || *ev.UserID != "test-user-id" {
		t.Errorf("event userID = %v, want %q", ev.UserID, "test-user-id")
	}
}
