package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"io"
	"os"
	"testing"

	"github.com/swayrider/authservice/internal/db"
	"github.com/swayrider/authservice/internal/model"
	"github.com/swayrider/grpcclients/mailclient"
	"github.com/swayrider/swlib/crypto"
	log "github.com/swayrider/swlib/logger"
)

func TestMain(m *testing.M) {
	log.SetOutput(io.Discard)
	os.Exit(m.Run())
}

var (
	testPrivateKeyPEM string
	testPasswordHash  string
	testSecretHash    string
)

const (
	testPassword = "TestP@ssw0rd!SecureEnough"
	testSecret   = "TestS3cret!SecureEnough1234"
)

func init() {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic("failed to generate test RSA key: " + err.Error())
	}
	keyBytes := x509.MarshalPKCS1PrivateKey(key)
	testPrivateKeyPEM = string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyBytes,
	}))

	testPasswordHash, err = crypto.CalculatePasswordHash(testPassword)
	if err != nil {
		panic("failed to compute test password hash: " + err.Error())
	}

	testSecretHash, err = crypto.CalculatePasswordHash(testSecret)
	if err != nil {
		panic("failed to compute test secret hash: " + err.Error())
	}
}

func testUser() *model.UserInternal {
	return &model.UserInternal{
		User: model.User{
			ID:           "test-user-id",
			Email:        "test@example.com",
			IsVerified:   true,
			IsAdmin:      false,
			AccountLevel: "free",
		},
		PasswordHash: sql.NullString{String: testPasswordHash, Valid: true},
	}
}

func testServiceClient(scopes []string) *model.ServiceClientInternal {
	return &model.ServiceClientInternal{
		ServiceClient: model.ServiceClient{
			ClientID: "test-client-id",
			Name:     "test-client",
			Scopes:   scopes,
		},
		ClientSecretHash: sql.NullString{String: testSecretHash, Valid: true},
	}
}

func newTestServer(d Database, m MailSender) *AuthServer {
	return NewAuthServer(d, log.New(), m, "from@example.com", "open", "", "", "")
}

// =============================================================================
// noopMailSender
// =============================================================================

type noopMailSender struct{}

func (n *noopMailSender) SendTemplateInternal(_ *mailclient.TemplateMail) (string, error) {
	return "", nil
}

// =============================================================================
// mockDB — implements Database with configurable per-method function fields
// =============================================================================

type mockDB struct {
	adminExistsFn             func(ctx context.Context) (bool, error)
	createAdminUserFn         func(ctx context.Context, email, hashedPassword string) (string, error)
	registerUserFn            func(ctx context.Context, email, hashedPassword string) (string, error)
	getUserByEmailFn          func(ctx context.Context, email string) (*model.UserInternal, error)
	getUserByIDFn             func(ctx context.Context, id string) (*model.UserInternal, error)
	markUserVerifiedFn        func(ctx context.Context, userId string) error
	updatePasswordFn          func(ctx context.Context, userId, hashedPassword string) error
	changeAccountLevelFn      func(ctx context.Context, userId, accountLevel string) error
	createRefreshTokenFn      func(ctx context.Context, user *model.User, jwtID, ip, userAgent string) (*model.RefreshToken, error)
	getRefreshTokenFn         func(ctx context.Context, token string) (*model.RefreshToken, error)
	deleteRefreshTokenFn      func(ctx context.Context, token string) error
	createVerificationTokenFn func(ctx context.Context, user *model.User) (*model.VerificationToken, error)
	getVerificationTokenFn    func(ctx context.Context, user *model.User) (*model.VerificationToken, error)
	deleteVerificationTokenFn func(ctx context.Context, userId string) error
	createResetPassTokenFn    func(ctx context.Context, user *model.User) (*model.PasswordResetToken, error)
	getResetPassTokenFn       func(ctx context.Context, user *model.User) (*model.PasswordResetToken, error)
	deleteResetPassTokenFn    func(ctx context.Context, userId string) error
	getSigningKeyFn           func(ctx context.Context) (string, error)
	getVerificationKeysFn     func(ctx context.Context) ([]string, error)
	createServiceClientFn     func(ctx context.Context, name, description string, scopes []string, secretHash string) (string, error)
	deleteServiceClientFn     func(ctx context.Context, clientId string) error
	getServiceClientByIDFn    func(ctx context.Context, clientID string) (*model.ServiceClientInternal, error)
	countServiceClientsFn     func(ctx context.Context) (int, error)
	listServiceClientsFn      func(ctx context.Context, page, pageSize int) ([]model.ServiceClient, error)
	createInviteFn            func(ctx context.Context, email string) (string, error)
	deleteInviteFn            func(ctx context.Context, email string) error
	consumeInviteFn           func(ctx context.Context, email string) error
	reInviteFn                func(ctx context.Context, email string) error
	getInviteByEmailFn        func(ctx context.Context, email string) (*model.Invite, error)
	isEmailInvitedFn          func(ctx context.Context, email string) (bool, error)
	countInvitesFn            func(ctx context.Context, registered *bool) (int, error)
	listInvitesFn             func(ctx context.Context, page, pageSize int, registered *bool) ([]model.Invite, error)
}

func (m *mockDB) AdminExists(ctx context.Context) (bool, error) {
	if m.adminExistsFn != nil {
		return m.adminExistsFn(ctx)
	}
	return false, nil
}
func (m *mockDB) CreateAdminUser(ctx context.Context, email, hashedPassword string) (string, error) {
	if m.createAdminUserFn != nil {
		return m.createAdminUserFn(ctx, email, hashedPassword)
	}
	return "", nil
}
func (m *mockDB) RegisterUser(ctx context.Context, email, hashedPassword string) (string, error) {
	if m.registerUserFn != nil {
		return m.registerUserFn(ctx, email, hashedPassword)
	}
	return "", nil
}
func (m *mockDB) GetUserByEmail(ctx context.Context, email string) (*model.UserInternal, error) {
	if m.getUserByEmailFn != nil {
		return m.getUserByEmailFn(ctx, email)
	}
	return nil, db.ErrUserNotFound
}
func (m *mockDB) GetUserByID(ctx context.Context, id string) (*model.UserInternal, error) {
	if m.getUserByIDFn != nil {
		return m.getUserByIDFn(ctx, id)
	}
	return nil, db.ErrUserNotFound
}
func (m *mockDB) MarkUserVerified(ctx context.Context, userId string) error {
	if m.markUserVerifiedFn != nil {
		return m.markUserVerifiedFn(ctx, userId)
	}
	return nil
}
func (m *mockDB) UpdatePassword(ctx context.Context, userId, hashedPassword string) error {
	if m.updatePasswordFn != nil {
		return m.updatePasswordFn(ctx, userId, hashedPassword)
	}
	return nil
}
func (m *mockDB) ChangeAccountLevel(ctx context.Context, userId, accountLevel string) error {
	if m.changeAccountLevelFn != nil {
		return m.changeAccountLevelFn(ctx, userId, accountLevel)
	}
	return nil
}
func (m *mockDB) CreateRefreshToken(ctx context.Context, user *model.User, jwtID, ip, userAgent string) (*model.RefreshToken, error) {
	if m.createRefreshTokenFn != nil {
		return m.createRefreshTokenFn(ctx, user, jwtID, ip, userAgent)
	}
	return &model.RefreshToken{Token: "mock-refresh-token"}, nil
}
func (m *mockDB) GetRefreshToken(ctx context.Context, token string) (*model.RefreshToken, error) {
	if m.getRefreshTokenFn != nil {
		return m.getRefreshTokenFn(ctx, token)
	}
	return nil, db.ErrNoRefreshTokenFound
}
func (m *mockDB) DeleteRefreshToken(ctx context.Context, token string) error {
	if m.deleteRefreshTokenFn != nil {
		return m.deleteRefreshTokenFn(ctx, token)
	}
	return nil
}
func (m *mockDB) CreateVerificationToken(ctx context.Context, user *model.User) (*model.VerificationToken, error) {
	if m.createVerificationTokenFn != nil {
		return m.createVerificationTokenFn(ctx, user)
	}
	return nil, nil
}
func (m *mockDB) GetVerificationToken(ctx context.Context, user *model.User) (*model.VerificationToken, error) {
	if m.getVerificationTokenFn != nil {
		return m.getVerificationTokenFn(ctx, user)
	}
	return nil, db.ErrNoVerificationTokenFound
}
func (m *mockDB) DeleteVerificationToken(ctx context.Context, userId string) error {
	if m.deleteVerificationTokenFn != nil {
		return m.deleteVerificationTokenFn(ctx, userId)
	}
	return nil
}
func (m *mockDB) CreateResetPasswordToken(ctx context.Context, user *model.User) (*model.PasswordResetToken, error) {
	if m.createResetPassTokenFn != nil {
		return m.createResetPassTokenFn(ctx, user)
	}
	return nil, nil
}
func (m *mockDB) GetResetPasswordToken(ctx context.Context, user *model.User) (*model.PasswordResetToken, error) {
	if m.getResetPassTokenFn != nil {
		return m.getResetPassTokenFn(ctx, user)
	}
	return nil, db.ErrNoPasswordResetTokenFound
}
func (m *mockDB) DeleteResetPasswordToken(ctx context.Context, userId string) error {
	if m.deleteResetPassTokenFn != nil {
		return m.deleteResetPassTokenFn(ctx, userId)
	}
	return nil
}
func (m *mockDB) GetSigningKey(ctx context.Context) (string, error) {
	if m.getSigningKeyFn != nil {
		return m.getSigningKeyFn(ctx)
	}
	return testPrivateKeyPEM, nil
}
func (m *mockDB) GetVerificationKeys(ctx context.Context) ([]string, error) {
	if m.getVerificationKeysFn != nil {
		return m.getVerificationKeysFn(ctx)
	}
	return nil, nil
}
func (m *mockDB) CreateServiceClient(ctx context.Context, name, description string, scopes []string, secretHash string) (string, error) {
	if m.createServiceClientFn != nil {
		return m.createServiceClientFn(ctx, name, description, scopes, secretHash)
	}
	return "new-client-id", nil
}
func (m *mockDB) DeleteServiceClient(ctx context.Context, clientId string) error {
	if m.deleteServiceClientFn != nil {
		return m.deleteServiceClientFn(ctx, clientId)
	}
	return nil
}
func (m *mockDB) GetServiceClientByID(ctx context.Context, clientID string) (*model.ServiceClientInternal, error) {
	if m.getServiceClientByIDFn != nil {
		return m.getServiceClientByIDFn(ctx, clientID)
	}
	return nil, db.ErrServiceClientNotFound
}
func (m *mockDB) CountServiceClients(ctx context.Context) (int, error) {
	if m.countServiceClientsFn != nil {
		return m.countServiceClientsFn(ctx)
	}
	return 0, nil
}
func (m *mockDB) ListServiceClients(ctx context.Context, page, pageSize int) ([]model.ServiceClient, error) {
	if m.listServiceClientsFn != nil {
		return m.listServiceClientsFn(ctx, page, pageSize)
	}
	return nil, nil
}
func (m *mockDB) CreateInvite(ctx context.Context, email string) (string, error) {
	if m.createInviteFn != nil {
		return m.createInviteFn(ctx, email)
	}
	return "", nil
}
func (m *mockDB) DeleteInvite(ctx context.Context, email string) error {
	if m.deleteInviteFn != nil {
		return m.deleteInviteFn(ctx, email)
	}
	return nil
}
func (m *mockDB) ConsumeInvite(ctx context.Context, email string) error {
	if m.consumeInviteFn != nil {
		return m.consumeInviteFn(ctx, email)
	}
	return nil
}
func (m *mockDB) ReInvite(ctx context.Context, email string) error {
	if m.reInviteFn != nil {
		return m.reInviteFn(ctx, email)
	}
	return nil
}
func (m *mockDB) GetInviteByEmail(ctx context.Context, email string) (*model.Invite, error) {
	if m.getInviteByEmailFn != nil {
		return m.getInviteByEmailFn(ctx, email)
	}
	return nil, db.ErrInviteNotFound
}
func (m *mockDB) IsEmailInvited(ctx context.Context, email string) (bool, error) {
	if m.isEmailInvitedFn != nil {
		return m.isEmailInvitedFn(ctx, email)
	}
	return false, nil
}
func (m *mockDB) CountInvites(ctx context.Context, registered *bool) (int, error) {
	if m.countInvitesFn != nil {
		return m.countInvitesFn(ctx, registered)
	}
	return 0, nil
}
func (m *mockDB) ListInvites(ctx context.Context, page, pageSize int, registered *bool) ([]model.Invite, error) {
	if m.listInvitesFn != nil {
		return m.listInvitesFn(ctx, page, pageSize, registered)
	}
	return nil, nil
}
