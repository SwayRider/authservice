// ping.go implements simple ping endpoints for connectivity testing.
//
// These endpoints can be used to verify basic service connectivity
// without performing any authentication or database operations.

package server

import (
	"context"

	healthv1 "github.com/swayrider/protos/health/v1"
)

// Ping responds with an empty response to verify HealthService connectivity.
func (*HealthServer) Ping(
	ctx context.Context,
	req *healthv1.PingRequest,
) (*healthv1.PingResponse, error) {
	return &healthv1.PingResponse{}, nil
}
