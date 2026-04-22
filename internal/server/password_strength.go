// password_strength.go implements the password strength checking endpoint.
//
// This allows clients to validate password strength before submitting
// registration or password change requests.

package server

import (
	"context"
	"fmt"

	passwordvalidator "github.com/wagslane/go-password-validator"

	authv1 "github.com/swayrider/protos/auth/v1"
	"github.com/swayrider/swlib/crypto"
)

// CheckPasswordStrength checks the strength of a password
//
// Parameters:
//   - ctx: The context of the request
//   - req: The request to check the strength of a password
//
// Returns:
//   - *authv1.CheckPasswordStrengthResponse: The response from the check password strength request
//   - error: An error if the request fails
func (s *AuthServer) CheckPasswordStrength(
	ctx context.Context,
	req *authv1.CheckPasswordStrengthRequest,
) (*authv1.CheckPasswordStrengthResponse, error) {
	err := passwordvalidator.Validate(req.Password, crypto.PasswordMinEntropy)
	if err != nil {
		return &authv1.CheckPasswordStrengthResponse{
			IsStrong: false,
			Message:  fmt.Sprintf("Password is too weak: %v", err),
		}, nil
	}
	return &authv1.CheckPasswordStrengthResponse{
		IsStrong: true,
		Message:  "Password is strong enough",
	}, nil
}
