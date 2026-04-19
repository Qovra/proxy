package backend

import (
	"context"
	"sync/atomic"
)

// Pool manages a set of backends with atomic round-robin selection,
// automatically skipping unhealthy backends.
type Pool struct {
	backends []*Backend
	counter  atomic.Uint64
	cancel   context.CancelFunc
}

// NewPool creates a Pool and starts a health-check goroutine for each address.
func NewPool(addresses []string) *Pool {
	ctx, cancel := context.WithCancel(context.Background())
	backends := make([]*Backend, len(addresses))
	for i, addr := range addresses {
		backends[i] = New(ctx, addr)
	}
	return &Pool{
		backends: backends,
		cancel:   cancel,
	}
}

// Next returns the address of the next healthy backend using round-robin.
// It scans all backends starting from the current counter position.
// Returns ("", false) if every backend is currently unhealthy.
func (p *Pool) Next() (string, bool) {
	n := uint64(len(p.backends))
	if n == 0 {
		return "", false
	}
	start := p.counter.Add(1) - 1
	for i := uint64(0); i < n; i++ {
		b := p.backends[(start+i)%n]
		if b.IsHealthy() {
			return b.Address(), true
		}
	}
	return "", false
}

// Status returns a snapshot of the health state of all backends in the pool.
func (p *Pool) Status() []BackendStatus {
	out := make([]BackendStatus, len(p.backends))
	for i, b := range p.backends {
		out[i] = b.Status()
	}
	return out
}

// Stop terminates all backend health-check goroutines.
func (p *Pool) Stop() {
	p.cancel()
}
