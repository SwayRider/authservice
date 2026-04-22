// errors.go defines sentinel errors for database operations.
//
// These errors allow callers to distinguish between different failure modes
// using errors.Is() for proper error handling.

package db

import "errors"

// Sentinel errors for database operations.
var (
	ErrUniqueViolation = errors.New("unique violation")

	ErrUserNotFound              = errors.New("user not found")
	ErrInvalidPassword           = errors.New("invalid password")
	ErrNoVerificationTokenFound  = errors.New("no verification token found")
	ErrNoRefreshTokenFound       = errors.New("no refresh token found")
	ErrNoPasswordResetTokenFound = errors.New("no password reset token found")
	ErrServiceClientNotFound     = errors.New("service client not found")
)
