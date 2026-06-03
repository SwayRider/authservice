package server

import (
	"context"
	"testing"

	authv1 "github.com/swayrider/protos/auth/v1"
)

// =============================================================================
// CheckPasswordStrength Tests
// =============================================================================

func TestCheckPasswordStrength(t *testing.T) {
	srv := newTestServer(nil, nil)
	ctx := context.Background()

	tests := []struct {
		name     string
		password string
		wantStrong bool
	}{
		{"short weak password", "abc", false},
		{"common password", "password123", false},
		{"keyboard walk", "qwerty123", false},
		{"strong password", "Tr0ub4dour&3-correct-horse", true},
		{"long random", "x7#Kp!mN2$qL8vRw", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := srv.CheckPasswordStrength(ctx, &authv1.CheckPasswordStrengthRequest{
				Password: tt.password,
			})
			if err != nil {
				t.Fatalf("CheckPasswordStrength returned unexpected error: %v", err)
			}
			if resp.IsStrong != tt.wantStrong {
				t.Errorf("IsStrong = %v, want %v (message: %s)", resp.IsStrong, tt.wantStrong, resp.Message)
			}
		})
	}
}
