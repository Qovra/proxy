package backend_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/Qovra/core/internal/backend"
)

// --- helpers ---

// listenUDP binds a real UDP socket on a random port and returns the address
// and a cancel func that closes the socket.
func listenUDP(t *testing.T) (addr string, close func()) {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listenUDP: %v", err)
	}
	return conn.LocalAddr().String(), func() { conn.Close() }
}

// unusedUDPAddr returns an address where nothing is listening.
func unusedUDPAddr(t *testing.T) string {
	t.Helper()
	// Bind then immediately close — the OS will free the port.
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("unusedUDPAddr: %v", err)
	}
	addr := conn.LocalAddr().String()
	conn.Close()
	return addr
}

// --- Backend ---

func TestBackend_InitiallyHealthy(t *testing.T) {
	addr, closeServer := listenUDP(t)
	defer closeServer()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	b := backend.New(ctx, addr)
	defer b.Stop()

	if !b.IsHealthy() {
		t.Error("backend should start as healthy")
	}
	if b.Address() != addr {
		t.Errorf("Address() = %q, want %q", b.Address(), addr)
	}
}

func TestBackend_Status_Fields(t *testing.T) {
	addr, closeServer := listenUDP(t)
	defer closeServer()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	before := time.Now()
	b := backend.New(ctx, addr)
	defer b.Stop()

	s := b.Status()
	if s.Address != addr {
		t.Errorf("Status.Address = %q, want %q", s.Address, addr)
	}
	if !s.Healthy {
		t.Error("Status.Healthy should be true initially")
	}
	if s.LastCheck.Before(before) {
		t.Error("Status.LastCheck should be >= backend creation time")
	}
	if s.FailCount != 0 {
		t.Errorf("Status.FailCount = %d, want 0", s.FailCount)
	}
}

func TestBackend_Stop_DoesNotPanic(t *testing.T) {
	ctx := context.Background()
	b := backend.New(ctx, "127.0.0.1:19999")
	b.Stop()
	b.Stop() // double-stop must not panic
}

// --- Pool ---

func TestPool_Next_SingleHealthyBackend(t *testing.T) {
	addr, closeServer := listenUDP(t)
	defer closeServer()

	pool := backend.NewPool([]string{addr})
	defer pool.Stop()

	got, ok := pool.Next()
	if !ok {
		t.Fatal("Next() returned ok=false, want true")
	}
	if got != addr {
		t.Errorf("Next() = %q, want %q", got, addr)
	}
}

func TestPool_Next_ReturnsEmptyWhenNoBackends(t *testing.T) {
	pool := backend.NewPool([]string{})
	defer pool.Stop()

	_, ok := pool.Next()
	if ok {
		t.Error("Next() on empty pool should return ok=false")
	}
}

func TestPool_Next_RoundRobin(t *testing.T) {
	addr1, close1 := listenUDP(t)
	defer close1()
	addr2, close2 := listenUDP(t)
	defer close2()
	addr3, close3 := listenUDP(t)
	defer close3()

	pool := backend.NewPool([]string{addr1, addr2, addr3})
	defer pool.Stop()

	// All backends start healthy; collect 6 consecutive results.
	seen := map[string]int{}
	for i := 0; i < 6; i++ {
		got, ok := pool.Next()
		if !ok {
			t.Fatalf("Next() call %d returned ok=false", i)
		}
		seen[got]++
	}

	// Each backend should have been returned exactly twice.
	for _, addr := range []string{addr1, addr2, addr3} {
		if seen[addr] != 2 {
			t.Errorf("backend %s selected %d times, want 2", addr, seen[addr])
		}
	}
}

func TestPool_Status_ReturnsAllBackends(t *testing.T) {
	addr1, close1 := listenUDP(t)
	defer close1()
	addr2, close2 := listenUDP(t)
	defer close2()

	pool := backend.NewPool([]string{addr1, addr2})
	defer pool.Stop()

	statuses := pool.Status()
	if len(statuses) != 2 {
		t.Fatalf("Status() returned %d entries, want 2", len(statuses))
	}

	addrs := map[string]bool{addr1: true, addr2: true}
	for _, s := range statuses {
		if !addrs[s.Address] {
			t.Errorf("unexpected address in Status(): %s", s.Address)
		}
	}
}

func TestPool_Stop_DoesNotPanic(t *testing.T) {
	pool := backend.NewPool([]string{"127.0.0.1:19998"})
	pool.Stop()
	pool.Stop() // double-stop must not panic
}

// TestPool_HealthTransition verifies that a backend is marked unhealthy after
// failThreshold consecutive failed pings and then marked healthy again on a
// successful ping. We do this by directly exercising the Backend's exported
// surface (Status + IsHealthy) after calling the internal check via the pool's
// loop — but since the loop is internal, we test indirectly through a real
// network scenario.
//
// Strategy:
//  1. Start a pool pointing to an address that has nothing listening.
//     The backend starts healthy (optimistic). Its first real health-check
//     happens only after 10 seconds, which is too slow for a unit test.
//  2. Instead, we use the Backend.Stop() trick: create a Backend directly via
//     New(), verify initial state, then indirectly test ping() by verifying
//     Status() fields are populated correctly at construction.
//
// Full ping-transition tests (10s timer) belong in integration tests.
// Here we just verify the Status snapshot is consistent with the initial state.
func TestPool_Status_InitiallyHealthy(t *testing.T) {
	addr, closeServer := listenUDP(t)
	defer closeServer()

	pool := backend.NewPool([]string{addr})
	defer pool.Stop()

	statuses := pool.Status()
	if len(statuses) != 1 {
		t.Fatalf("want 1 status, got %d", len(statuses))
	}
	s := statuses[0]
	if !s.Healthy {
		t.Error("backend should start healthy")
	}
	if s.FailCount != 0 {
		t.Errorf("FailCount should be 0, got %d", s.FailCount)
	}
}

// TestPool_Next_SkipsUnhealthyOnReload simulates the "all backends unhealthy"
// path by creating a pool with only addresses that have nothing listening, then
// forcing the backends unhealthy by directly using the Backend exported API.
// Since we can't set healthy=false externally, we test this through the pool
// returning false when all backends start unhealthy.
//
// We do this by creating backends manually (via New) and passing them through
// the pool indirectly — but since Pool doesn't accept pre-built Backends, we
// test the behaviour using the Backend.IsHealthy() after a Stop (which doesn't
// change health). The real "all unhealthy → Drop" path is covered by the
// SNIRouterHandler integration scenario described in integration tests.
//
// Minimal coverage: verify Next() returns ok=false only when pool is empty.
func TestPool_Next_AllUnhealthyWhenEmpty(t *testing.T) {
	pool := backend.NewPool(nil)
	defer pool.Stop()

	_, ok := pool.Next()
	if ok {
		t.Error("expected ok=false for empty pool")
	}
}
