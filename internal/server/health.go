// health.go implements the health check endpoint.
//
// The health service provides a simple UP/DOWN status for load balancers
// and orchestration systems to verify the service is running. For "auth"
// (and "health"/""), status reflects real Postgres connectivity rather than
// unconditionally reporting UP.

package server

import (
	"context"
	"strings"
	"time"

	healthv1 "github.com/swayrider/protos/health/v1"
)

// dbPingTimeout bounds a single Postgres reachability probe.
const dbPingTimeout = 3 * time.Second

// Check returns the health status of the specified component.
// Returns UP/DOWN based on Postgres reachability for "auth", "health", or
// empty component name; UNKNOWN otherwise.
func (h *HealthServer) Check(
	ctx context.Context,
	req *healthv1.HealthRequest,
) (*healthv1.HealthResponse, error) {
	switch strings.ToLower(req.Component) {
	case "auth", "health", "":
		status := healthv1.HealthResponse_DOWN
		if h.probeDB(ctx) {
			status = healthv1.HealthResponse_UP
		}
		return &healthv1.HealthResponse{Status: status}, nil
	default:
		return &healthv1.HealthResponse{
			Status: healthv1.HealthResponse_UNKNOWN,
		}, nil
	}
}

// probeDB reports whether the database is reachable, reusing the last probe
// result while it is younger than h.probeTTL to avoid pinging the database
// on every health check.
func (h *HealthServer) probeDB(ctx context.Context) bool {
	h.mu.Lock()
	if time.Since(h.lastCheck) < h.probeTTL {
		up := h.lastUp
		h.mu.Unlock()
		return up
	}
	h.mu.Unlock()

	pingCtx, cancel := context.WithTimeout(ctx, dbPingTimeout)
	defer cancel()

	err := h.db.PingContext(pingCtx)
	up := err == nil
	if !up {
		h.l.Errorf("database health probe failed: %v", err)
	}

	h.mu.Lock()
	h.lastCheck = time.Now()
	h.lastUp = up
	h.mu.Unlock()

	return up
}
