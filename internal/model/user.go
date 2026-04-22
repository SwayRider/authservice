// Package model defines data structures for the authservice.
//
// This package contains domain models for users, tokens, and service clients.
// Models are designed to separate public information from internal/sensitive data
// using embedded structs (e.g., User vs UserInternal).

package model

import (
	"database/sql"
	"time"
)

// User represents the public user profile information.
// This struct contains only fields safe to expose in API responses.
type User struct {
	ID           string         // UUID - unique user identifier
	Email        string         // User's email address
	Provider     string         // Auth provider: "email", "google", "facebook", ...
	ProviderID   sql.NullString // External provider's user ID (e.g., Google user ID)
	IsVerified   bool           // Whether email has been verified
	IsAdmin      bool           // Whether user has admin privileges
	AccountLevel string         // Subscription tier: "free", "premium", ...
}

// UserInternal extends User with sensitive fields needed for authentication.
// This struct is used internally and should never be exposed via API.
type UserInternal struct {
	User                        // Embedded public user fields
	PasswordHash sql.NullString // Argon2id password hash (null for OAuth users)
	CreatedAt    time.Time      // Account creation timestamp
	UpdatedAt    time.Time      // Last modification timestamp
}
