// Package svctoken mints short-lived service tokens for authservice's own
// service-to-service calls to other SwayRider services.
package svctoken

import (
	"context"
	"time"

	"github.com/swayrider/swlib/jwt"
)

// mailSendSubject identifies authservice as the token holder in tokens minted
// by MailSendToken.
const mailSendSubject = "authservice"

// SigningKeyProvider is satisfied by both the server package's Database
// interface and *db.DB directly. It is declared locally, scoped to just the
// method this package needs, so svctoken has no dependency on either.
type SigningKeyProvider interface {
	GetSigningKey(ctx context.Context) (string, error)
}

// MailSendToken mints a short-lived service token scoped for mailservice's
// authenticated Send/SendTemplate RPCs (scope "email:send").
//
// Unlike the client-credentials flow exposed by GetToken, authservice signs
// this itself: it already holds the signing key and is calling on its own
// behalf, not authenticating an external caller, so there is no need for a
// registered ServiceClient/secret or a self-directed round trip through its
// own GetToken RPC.
func MailSendToken(ctx context.Context, keys SigningKeyProvider) (string, error) {
	pk, err := keys.GetSigningKey(ctx)
	if err != nil {
		return "", err
	}

	openID := &jwt.OpenIDClaims{}
	openID.SetAuthTime(time.Now())
	claims := jwt.NewSwayRiderServiceClaims([]string{"email:send"})

	_, token, _, err := jwt.GenerateToken(mailSendSubject, openID, claims, pk, jwt.DefaultTTL)
	if err != nil {
		return "", err
	}
	return string(token), nil
}
