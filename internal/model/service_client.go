// service_client.go defines models for service-to-service authentication.
//
// Service clients authenticate using OAuth2 client credentials flow with
// a client ID and secret. Each client has a list of scopes that define
// which operations it can perform.

package model

import (
	"database/sql"
	"time"
)

// ServiceClient represents the public service client information.
// This struct is safe to expose in API responses.
type ServiceClient struct {
	ClientID    string   // Unique client identifier (32-byte random string)
	Name        string   // Human-readable client name
	Description string   // Description of the client's purpose
	Scopes      []string // List of permitted operation scopes
}

// ServiceClientInternal extends ServiceClient with sensitive fields.
// This struct is used for authentication and should never be exposed.
type ServiceClientInternal struct {
	ServiceClient                  // Embedded public client fields
	ClientSecretHash sql.NullString // Argon2id hash of the client secret
	CreatedAt        time.Time      // Client creation timestamp
}
