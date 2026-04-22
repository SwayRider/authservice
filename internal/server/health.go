// health.go implements the health check endpoint.
//
// The health service provides a simple UP/DOWN status for load balancers
// and orchestration systems to verify the service is running.

package server

import (
	"context"
	"strings"

	healthv1 "github.com/swayrider/protos/health/v1"
)

// Check returns the health status of the specified component.
// Returns UP for "auth", "health", or empty component name; UNKNOWN otherwise.
func (h *HealthServer) Check(
	ctx context.Context,
	req *healthv1.HealthRequest,
) (*healthv1.HealthResponse, error) {
	switch strings.ToLower(req.Component) {
	case "auth", "health", "":
		return &healthv1.HealthResponse{
			Status: healthv1.HealthResponse_UP,
		}, nil
	default:
		return &healthv1.HealthResponse{
			Status: healthv1.HealthResponse_UNKNOWN,
		}, nil
	}
}
