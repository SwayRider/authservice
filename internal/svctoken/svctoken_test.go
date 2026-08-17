package svctoken

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"

	"github.com/swayrider/swlib/jwt"
)

type stubKeyProvider struct {
	pem string
	err error
}

func (s stubKeyProvider) GetSigningKey(_ context.Context) (string, error) {
	return s.pem, s.err
}

func testPrivateKeyPEM(t *testing.T) (privatePEM, publicPEM string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test RSA key: %v", err)
	}
	privatePEM = string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}))
	pubBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal test public key: %v", err)
	}
	publicPEM = string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	}))
	return
}

func TestMailSendToken_ScopedToEmailSend(t *testing.T) {
	privatePEM, publicPEM := testPrivateKeyPEM(t)

	token, err := MailSendToken(context.Background(), stubKeyProvider{pem: privatePEM})
	if err != nil {
		t.Fatalf("MailSendToken returned unexpected error: %v", err)
	}

	claims, err := jwt.VerifyToken(token, publicPEM, jwt.VerifyDefault)
	if err != nil {
		t.Fatalf("failed to verify minted token: %v", err)
	}
	if claims.Subject != mailSendSubject {
		t.Errorf("subject = %q, want %q", claims.Subject, mailSendSubject)
	}

	serviceClaims, ok := claims.SwayRiderClaims.(*jwt.SwayRiderServiceClaims)
	if !ok {
		t.Fatalf("SwayRiderClaims type = %T, want *jwt.SwayRiderServiceClaims", claims.SwayRiderClaims)
	}
	if got := []string(serviceClaims.Scopes); len(got) != 1 || got[0] != "email:send" {
		t.Errorf("scopes = %v, want [email:send]", got)
	}
}

func TestMailSendToken_SigningKeyError(t *testing.T) {
	wantErr := errors.New("signing key unavailable")

	_, err := MailSendToken(context.Background(), stubKeyProvider{err: wantErr})
	if !errors.Is(err, wantErr) {
		t.Errorf("error = %v, want %v", err, wantErr)
	}
}
