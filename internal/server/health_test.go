package server

import (
	"context"
	"errors"
	"testing"
	"time"

	healthv1 "github.com/swayrider/protos/health/v1"
)

// =============================================================================
// Ping Tests
// =============================================================================

func TestPing(t *testing.T) {
	h := newTestHealthServer(&mockPinger{}, time.Second)
	resp, err := h.Ping(context.Background(), &healthv1.PingRequest{})
	if err != nil {
		t.Fatalf("Ping returned error: %v", err)
	}
	if resp == nil {
		t.Fatal("Ping returned nil response")
	}
}

// =============================================================================
// Check Tests
// =============================================================================

func TestCheck_UnknownComponent(t *testing.T) {
	h := newTestHealthServer(&mockPinger{}, time.Second)

	for _, component := range []string{"unknown", "postgres", "database"} {
		t.Run(component, func(t *testing.T) {
			resp, err := h.Check(context.Background(), &healthv1.HealthRequest{Component: component})
			if err != nil {
				t.Fatalf("Check(%q) returned error: %v", component, err)
			}
			if resp.Status != healthv1.HealthResponse_UNKNOWN {
				t.Errorf("Check(%q).Status = %v, want %v", component, resp.Status, healthv1.HealthResponse_UNKNOWN)
			}
		})
	}
}

func TestCheck_ReportsUpWhenDBReachable(t *testing.T) {
	h := newTestHealthServer(&mockPinger{}, time.Second)

	for _, component := range []string{"auth", "AUTH", "health", "HEALTH", ""} {
		t.Run(component, func(t *testing.T) {
			resp, err := h.Check(context.Background(), &healthv1.HealthRequest{Component: component})
			if err != nil {
				t.Fatalf("Check(%q) returned error: %v", component, err)
			}
			if resp.Status != healthv1.HealthResponse_UP {
				t.Errorf("Check(%q).Status = %v, want %v", component, resp.Status, healthv1.HealthResponse_UP)
			}
		})
	}
}

func TestCheck_ReportsDownWhenDBUnreachable(t *testing.T) {
	p := &mockPinger{pingFn: func(ctx context.Context) error {
		return errors.New("connection refused")
	}}
	h := newTestHealthServer(p, time.Second)

	resp, err := h.Check(context.Background(), &healthv1.HealthRequest{Component: "auth"})
	if err != nil {
		t.Fatalf("Check returned error: %v", err)
	}
	if resp.Status != healthv1.HealthResponse_DOWN {
		t.Errorf("Check.Status = %v, want %v", resp.Status, healthv1.HealthResponse_DOWN)
	}
}

func TestCheck_CachesProbeResultWithinTTL(t *testing.T) {
	var calls int
	p := &mockPinger{pingFn: func(ctx context.Context) error {
		calls++
		return errors.New("connection refused")
	}}
	// Long TTL: the second Check below must reuse the first probe result
	// rather than pinging again.
	h := newTestHealthServer(p, time.Hour)

	if _, err := h.Check(context.Background(), &healthv1.HealthRequest{Component: "auth"}); err != nil {
		t.Fatalf("first Check returned error: %v", err)
	}
	if _, err := h.Check(context.Background(), &healthv1.HealthRequest{Component: "auth"}); err != nil {
		t.Fatalf("second Check returned error: %v", err)
	}

	if calls != 1 {
		t.Errorf("PingContext called %d times, want 1 (second Check should have used the cache)", calls)
	}
}

func TestCheck_ReprobesAfterTTLExpires(t *testing.T) {
	var calls int
	p := &mockPinger{pingFn: func(ctx context.Context) error {
		calls++
		return nil
	}}
	h := newTestHealthServer(p, time.Millisecond)

	if _, err := h.Check(context.Background(), &healthv1.HealthRequest{Component: "auth"}); err != nil {
		t.Fatalf("first Check returned error: %v", err)
	}

	time.Sleep(5 * time.Millisecond)

	if _, err := h.Check(context.Background(), &healthv1.HealthRequest{Component: "auth"}); err != nil {
		t.Fatalf("second Check returned error: %v", err)
	}

	if calls != 2 {
		t.Errorf("PingContext called %d times, want 2 (TTL should have expired before the second Check)", calls)
	}
}
