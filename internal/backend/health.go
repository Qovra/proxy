package backend

import (
	"context"
	"log"
	"net"
	"sync/atomic"
	"time"
)

const (
	checkInterval  = 10 * time.Second
	pingTimeout    = 500 * time.Millisecond
	failThreshold  = 3
)

// BackendStatus is a point-in-time snapshot of a backend's health state.
type BackendStatus struct {
	Address   string    `json:"address"`
	Healthy   bool      `json:"healthy"`
	LastCheck time.Time `json:"last_check"`
	FailCount int32     `json:"fail_count"`
}

// Backend represents a single upstream server with UDP health checking.
type Backend struct {
	address   string
	healthy   atomic.Bool
	lastCheck atomic.Int64 // Unix nanoseconds
	failCount atomic.Int32
	cancel    context.CancelFunc
}

// New creates a Backend and starts its periodic health-check goroutine.
// The backend begins in a healthy state (optimistic assumption).
// The goroutine runs until the provided context is cancelled or Stop is called.
func New(ctx context.Context, address string) *Backend {
	childCtx, cancel := context.WithCancel(ctx)
	b := &Backend{
		address: address,
		cancel:  cancel,
	}
	b.healthy.Store(true)
	b.lastCheck.Store(time.Now().UnixNano())

	go b.loop(childCtx)
	return b
}

// Address returns the backend's address string.
func (b *Backend) Address() string { return b.address }

// IsHealthy reports whether the backend is currently considered healthy.
func (b *Backend) IsHealthy() bool { return b.healthy.Load() }

// Status returns a snapshot of this backend's current health state.
func (b *Backend) Status() BackendStatus {
	return BackendStatus{
		Address:   b.address,
		Healthy:   b.healthy.Load(),
		LastCheck: time.Unix(0, b.lastCheck.Load()),
		FailCount: b.failCount.Load(),
	}
}

// Stop terminates the health-check goroutine.
func (b *Backend) Stop() { b.cancel() }

func (b *Backend) loop(ctx context.Context) {
	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			b.check()
		}
	}
}

func (b *Backend) check() {
	b.lastCheck.Store(time.Now().UnixNano())

	ok := b.ping()
	wasHealthy := b.healthy.Load()

	if ok {
		b.failCount.Store(0)
		if !wasHealthy {
			b.healthy.Store(true)
			log.Printf("[backend] %s HEALTHY  at %s",
				b.address, time.Now().Format(time.RFC3339))
		}
		return
	}

	// Probe failed.
	fails := b.failCount.Add(1)
	if wasHealthy && fails >= failThreshold {
		b.healthy.Store(false)
		log.Printf("[backend] %s UNHEALTHY (consecutive_failures=%d) at %s",
			b.address, fails, time.Now().Format(time.RFC3339))
	}
}

// ping sends a single UDP probe to the backend address.
//
// Return value semantics:
//   - true  → healthy: either received a reply, or the read timed out (expected
//     behaviour for QUIC/game servers that silently drop unknown probes).
//   - false → unhealthy: dial failed, write failed, or received an ICMP error
//     such as "connection refused" or "network unreachable".
func (b *Backend) ping() bool {
	conn, err := net.Dial("udp", b.address)
	if err != nil {
		return false
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(pingTimeout)); err != nil {
		return false
	}
	if _, err := conn.Write([]byte{0}); err != nil {
		return false
	}

	buf := [1]byte{}
	_, err = conn.Read(buf[:])
	if err == nil {
		return true // got a reply
	}
	// A read timeout means the server is reachable but ignoring our probe.
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return true
	}
	// Any other error (ICMP port unreachable, etc.) → unhealthy.
	return false
}
