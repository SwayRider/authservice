// viewdata.go provides template data preparation for web pages.
//
// This file handles extracting query parameters, setting up internationalization,
// and providing helper functions for templates.

package web

import (
	"net/http"
	"strings"

	"github.com/swayrider/swlib/jwt"
	"github.com/swayrider/swlib/security"
)

// viewData prepares template data from the HTTP request.
// It extracts query parameters, sets up i18n, and adds helper functions.
// Internal parameters (prefixed with "sw_") are stripped from the URL params.
func viewData(r *http.Request) map[string]any {
	params := make(map[string]any)
	for key, values := range r.URL.Query() {
		if len(values) > 0 {
			params[key] = values[0]
		}
	}

	if _, ok := params["lang"]; !ok {
		params["lang"] = "en"
	}

	lang := params["lang"].(string)
	if _, ok := translations[lang]; !ok {
		lang = "en"
		params["lang"] = lang
	}

	// Strip internal parameters
	for key := range params {
		if strings.HasPrefix(key, "sw_") {
			delete(params, key)
		}
	}
	
	params["sw_i18n"] = translator(lang)
	params["sw_isMobileAppBrowser"] = isMobileAppBrowser(r)
	params["sw_isEmailVerified"] = isEmailVerified
	if isMobileAppBrowser(r) {
		params["sw_appURL"] = getAppURL()
	}

	ctx := r.Context()
	claimsKey := security.ClaimsKey
	if claims, ok := ctx.Value(claimsKey).(*jwt.Claims); ok {
		params["sw_userClaims"] = claims
	}

	return params
}

// isMobileAppBrowser checks if the request comes from a mobile device.
func isMobileAppBrowser(r *http.Request) bool {
	ua := strings.ToLower(r.Header.Get("User-Agent"))
	return strings.Contains(ua, "android") || strings.Contains(ua, "ios") || strings.Contains(ua, "iphone") || strings.Contains(ua, "ipad")
}

// isEmailVerified checks if the user's email is verified based on JWT claims.
func isEmailVerified(userClaims *jwt.Claims) bool {
	return userClaims != nil && userClaims.EmailVerified != nil && *userClaims.EmailVerified
}

// getAppURL returns the deep link URL for the SwayRider mobile app.
func getAppURL() string {
	return "swayrider://home"
}

