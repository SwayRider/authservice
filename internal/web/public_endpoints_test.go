package web

import (
	"net/http"
	"testing"

	"github.com/swayrider/swlib/security"
)

// TestPublicWebEndpoints pins that the email-verified web pages are reachable
// anonymously. The "/web/reset-mfa" page in particular was the source of a
// 401 "unauthorized" for users who clicked the emailed reset link while not
// logged in: it was never registered as a public endpoint, so
// middlewares.Auth hard-401'd the anonymous GET. This test fails loudly if a
// page is dropped from registerEndpointProfiles or if the WEB_PATH_PREFIX used
// to register it doesn't match the one the mux/handler is mounted under.
func TestPublicWebEndpoints(t *testing.T) {
	cases := []struct {
		name   string
		prefix string
	}{
		{name: "default /web prefix", prefix: "/web/"},
		{name: "root prefix", prefix: "/"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			registerEndpointProfiles(tc.prefix)

			// The pages a logged-out user must be able to open directly.
			publicPages := []string{
				tc.prefix + "verify-user",
				tc.prefix + "reset-password",
				tc.prefix + "reset-mfa",
				tc.prefix + "register",
			}
			for _, ep := range publicPages {
				profile := security.GetEndpointProfileForMethod(ep, http.MethodGet)
				if !profile.AllowPublic {
					t.Errorf("endpoint %q is not registered as public (AllowPublic=false); anonymous access would 401", ep)
				}
			}
		})
	}
}
