package model

import "time"

// Invite represents a pre-approved email address that may register an account.
type Invite struct {
	ID         string
	Email      string
	CreatedAt  time.Time
	Registered bool
}
