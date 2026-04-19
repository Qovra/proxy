package handler_test

import (
	"encoding/json"
	"net"
	"sync"
	"testing"

	"github.com/Qovra/core/internal/handler"
)

// --- helpers ---

func newConnLimitHandler(t *testing.T, maxConns, burst int) *handler.IPConnLimitHandler {
	t.Helper()
	raw, _ := json.Marshal(map[string]int{
		"max_conns_per_ip": maxConns,
		"burst":            burst,
	})
	h, err := handler.NewIPConnLimitHandler(raw)
	if err != nil {
		t.Fatalf("NewIPConnLimitHandler: %v", err)
	}
	return h.(*handler.IPConnLimitHandler)
}

func newCtx(ip string) *handler.Context {
	return &handler.Context{
		ClientAddr: &net.UDPAddr{IP: net.ParseIP(ip), Port: 1234},
	}
}

func connect(h *handler.IPConnLimitHandler, ctx *handler.Context) handler.Result {
	return h.OnConnect(ctx)
}

func disconnect(h *handler.IPConnLimitHandler, ctx *handler.Context) {
	h.OnDisconnect(ctx)
}

func assertContinue(t *testing.T, r handler.Result, msg string) {
	t.Helper()
	if r.Action != handler.Continue {
		t.Errorf("%s: expected Continue, got %v (err: %v)", msg, r.Action, r.Error)
	}
}

func assertDrop(t *testing.T, r handler.Result, msg string) {
	t.Helper()
	if r.Action != handler.Drop {
		t.Errorf("%s: expected Drop, got %v", msg, r.Action)
	}
}

// --- constructor validation ---

func TestNewIPConnLimitHandler_InvalidConfig(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{"zero max_conns_per_ip", `{"max_conns_per_ip": 0}`},
		{"negative max_conns_per_ip", `{"max_conns_per_ip": -1}`},
		{"malformed json", `{bad}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := handler.NewIPConnLimitHandler(json.RawMessage(tc.raw))
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

func TestNewIPConnLimitHandler_NegativeBurstClamped(t *testing.T) {
	// Negative burst should be silently clamped to 0 (not an error).
	raw := json.RawMessage(`{"max_conns_per_ip": 5, "burst": -1}`)
	h, err := handler.NewIPConnLimitHandler(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cl := h.(*handler.IPConnLimitHandler)
	// Verify the handler accepts up to 5 normal, 0 burst.
	ip := "99.0.0.1"
	for i := 0; i < 5; i++ {
		assertContinue(t, cl.OnConnect(newCtx(ip)), "normal conn")
	}
	assertDrop(t, cl.OnConnect(newCtx(ip)), "burst must be 0 → drop on 6th")
}

// --- normal limit (no burst) ---

func TestConnLimit_NormalLimit_AllowsUpToMax(t *testing.T) {
	h := newConnLimitHandler(t, 3, 0)
	ip := "10.0.0.1"

	contexts := make([]*handler.Context, 3)
	for i := range contexts {
		contexts[i] = newCtx(ip)
		assertContinue(t, connect(h, contexts[i]), "connection "+string(rune('1'+i)))
	}
}

func TestConnLimit_NormalLimit_DropsOnExceed(t *testing.T) {
	h := newConnLimitHandler(t, 3, 0)
	ip := "10.0.0.1"

	for i := 0; i < 3; i++ {
		connect(h, newCtx(ip))
	}
	assertDrop(t, connect(h, newCtx(ip)), "4th connection over limit")
}

func TestConnLimit_NormalLimit_IsolatedPerIP(t *testing.T) {
	h := newConnLimitHandler(t, 2, 0)

	ctx1 := newCtx("192.168.1.1")
	ctx2 := newCtx("192.168.1.1")
	ctx3 := newCtx("192.168.1.2")
	ctx4 := newCtx("192.168.1.2")

	assertContinue(t, connect(h, ctx1), "ip1 conn1")
	assertContinue(t, connect(h, ctx2), "ip1 conn2")
	assertContinue(t, connect(h, ctx3), "ip2 conn1")
	assertContinue(t, connect(h, ctx4), "ip2 conn2")

	assertDrop(t, connect(h, newCtx("192.168.1.1")), "ip1 over limit")
	assertDrop(t, connect(h, newCtx("192.168.1.2")), "ip2 over limit")
}

// --- disconnect releases slot ---

func TestConnLimit_DisconnectReleasesSlot(t *testing.T) {
	h := newConnLimitHandler(t, 2, 0)
	ip := "10.0.0.5"

	ctx1 := newCtx(ip)
	ctx2 := newCtx(ip)
	assertContinue(t, connect(h, ctx1), "conn1")
	assertContinue(t, connect(h, ctx2), "conn2")

	assertDrop(t, connect(h, newCtx(ip)), "at limit")

	disconnect(h, ctx1)

	assertContinue(t, connect(h, newCtx(ip)), "after disconnect")
}

func TestConnLimit_DisconnectWithoutConnect_Noop(t *testing.T) {
	h := newConnLimitHandler(t, 3, 0)
	ctx := newCtx("10.0.0.9")
	disconnect(h, ctx) // must not panic or corrupt counters
}

// --- burst ---

func TestConnLimit_Burst_AllowsBeyondLimit(t *testing.T) {
	h := newConnLimitHandler(t, 2, 2) // normal=2, burst=2 → total=4
	ip := "10.1.0.1"

	contexts := make([]*handler.Context, 4)
	for i := range contexts {
		contexts[i] = newCtx(ip)
		assertContinue(t, connect(h, contexts[i]), "conn "+string(rune('1'+i)))
	}
}

func TestConnLimit_Burst_DropsAfterBurstExhausted(t *testing.T) {
	h := newConnLimitHandler(t, 2, 2) // max total = 4
	ip := "10.1.0.2"

	for i := 0; i < 4; i++ {
		connect(h, newCtx(ip))
	}
	assertDrop(t, connect(h, newCtx(ip)), "over burst limit")
}

func TestConnLimit_Burst_TokenReturnedOnDisconnect(t *testing.T) {
	h := newConnLimitHandler(t, 1, 1) // normal=1, burst=1 → total=2
	ip := "10.1.0.3"

	ctx1 := newCtx(ip)
	ctx2 := newCtx(ip) // consumes burst

	assertContinue(t, connect(h, ctx1), "normal conn")
	assertContinue(t, connect(h, ctx2), "burst conn")
	assertDrop(t, connect(h, newCtx(ip)), "at total limit")

	disconnect(h, ctx2) // burst token returned

	assertContinue(t, connect(h, newCtx(ip)), "burst token recovered")
}

func TestConnLimit_Burst_NormalDisconnectDoesNotReturnBurstToken(t *testing.T) {
	// max=2, burst=1 → total=3
	// State after setup: ctx1(normal) + ctx2(normal) + ctx3(burst) = 3 active
	// Disconnect ctx1 (normal) → 2 active, burst still consumed (1/1)
	// active(2) >= maxConns(2), burst(1/1) exhausted → next conn must DROP.
	// Only disconnecting ctx3 (burst) returns the burst token.
	h := newConnLimitHandler(t, 2, 1)
	ip := "10.1.0.4"

	ctx1 := newCtx(ip) // normal slot 1
	ctx2 := newCtx(ip) // normal slot 2
	ctx3 := newCtx(ip) // burst slot

	assertContinue(t, connect(h, ctx1), "normal 1")
	assertContinue(t, connect(h, ctx2), "normal 2")
	assertContinue(t, connect(h, ctx3), "burst")
	assertDrop(t, connect(h, newCtx(ip)), "total limit reached")

	// Disconnect a NORMAL connection.
	// active: 3→2, burst_used stays at 1/1.
	// active(2) == maxConns(2), burst exhausted → DROP.
	disconnect(h, ctx1)
	assertDrop(t, connect(h, newCtx(ip)), "normal disconnect does not free burst token")

	// Disconnect the BURST connection → burst token returned, active: 2→1.
	// active(1) < maxConns(2) → normal slot available → ALLOW.
	disconnect(h, ctx3)
	assertContinue(t, connect(h, newCtx(ip)), "burst token recovered after burst disconnect")
}

// --- concurrency ---

func TestConnLimit_Concurrent_NeverExceedsLimit(t *testing.T) {
	const (
		maxConns = 5
		burst    = 3
		workers  = 50
	)
	h := newConnLimitHandler(t, maxConns, burst)
	ip := "10.2.0.1"

	var (
		mu       sync.Mutex
		admitted int
		wg       sync.WaitGroup
	)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx := newCtx(ip)
			r := connect(h, ctx)
			if r.Action == handler.Continue {
				mu.Lock()
				admitted++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if admitted > maxConns+burst {
		t.Errorf("admitted %d connections, want <= %d", admitted, maxConns+burst)
	}

	// Internal counter must also be consistent.
	activeCount := h.ActiveConns(ip)
	if activeCount > int64(maxConns+burst) {
		t.Errorf("internal counter=%d, want <= %d", activeCount, maxConns+burst)
	}
}
