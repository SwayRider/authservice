package web

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/swayrider/swlib/security"
	log "github.com/swayrider/swlib/logger"
)

// TestWebServer_AnonymousNotRejected is the regression test for the
// "401 unauthorized" that locked out logged-out users clicking the MFA-reset
// email link. The web mux must admit anonymous requests regardless of whether
// a page is individually registered public or of any WEB_PATH_PREFIX quirk --
// every page it serves is a public email-verification page.
func TestWebServer_AnonymousNotRejected(t *testing.T) {
	// publicKeysFn that returns no keys: even a present-but-unverifiable
	// token must not cause a rejection.
	fn := func() ([]string, error) { return []string{}, nil }

	reached := false
	mw := withOptionalClaims(security.PublicKeysFn(fn), log.New())
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/web/reset-mfa?u=foo&t=bar", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !reached {
		t.Fatal("handler was not reached: the request was rejected before reaching the page (would 401 in production)")
	}
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (anonymous web request must not be rejected)", w.Code)
	}
}
