package handler

import (
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
)

func init() {
	Register("ip-connlimit", NewIPConnLimitHandler)
}

// ipConnEntry tracks active and burst-consumed connections for a single IP.
type ipConnEntry struct {
	active atomic.Int64 // current simultaneous connections
	burst  atomic.Int64 // burst tokens currently in use
	mu     sync.Mutex   // guards burst token reuse on disconnect
}

// IPConnLimitHandler enforces a hard limit on simultaneous connections per IP,
// with an optional burst allowance above the base limit.
//
// Semantics:
//   - active <= max_conns_per_ip              → allowed (normal)
//   - active >  max_conns_per_ip, burst left  → allowed (burst consumed)
//   - active >= max_conns_per_ip + burst      → dropped
//
// Burst tokens are returned when a burst-consuming connection closes, making
// them available again for future spikes.
type IPConnLimitHandler struct {
	maxConns int64
	burst    int64
	entries  sync.Map // ip string → *ipConnEntry
}

type ipConnLimitConfig struct {
	MaxConnsPerIP int `json:"max_conns_per_ip"`
	Burst         int `json:"burst"`
}

func NewIPConnLimitHandler(raw json.RawMessage) (Handler, error) {
	cfg := ipConnLimitConfig{
		MaxConnsPerIP: 10,
		Burst:         0,
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return nil, fmt.Errorf("invalid ip-connlimit config: %w", err)
		}
	}
	if cfg.MaxConnsPerIP <= 0 {
		return nil, fmt.Errorf("ip-connlimit: max_conns_per_ip must be > 0")
	}
	if cfg.Burst < 0 {
		cfg.Burst = 0
	}

	return &IPConnLimitHandler{
		maxConns: int64(cfg.MaxConnsPerIP),
		burst:    int64(cfg.Burst),
	}, nil
}

func (h *IPConnLimitHandler) Name() string { return "ip-connlimit" }

func (h *IPConnLimitHandler) OnConnect(ctx *Context) Result {
	ip := ctx.ClientAddr.IP.String()
	entry := h.getOrCreate(ip)

	entry.mu.Lock()
	defer entry.mu.Unlock()

	active := entry.active.Load()

	// Normal slot available.
	if active < h.maxConns {
		entry.active.Add(1)
		ctx.Set("_connlimit_ip", ip)
		ctx.Set("_connlimit_burst", false)
		return Result{Action: Continue}
	}

	// Try burst slot.
	if h.burst > 0 {
		used := entry.burst.Load()
		if used < h.burst {
			entry.active.Add(1)
			entry.burst.Add(1)
			ctx.Set("_connlimit_ip", ip)
			ctx.Set("_connlimit_burst", true)
			log.Printf("[ip-connlimit] burst connection allowed: ip=%s active=%d burst_used=%d/%d",
				ip, active+1, used+1, h.burst)
			return Result{Action: Continue}
		}
	}

	log.Printf("[ip-connlimit] connection limit exceeded: ip=%s active=%d limit=%d burst=%d",
		ip, active, h.maxConns, h.burst)
	return Result{Action: Drop, Error: fmt.Errorf("connection limit exceeded for ip %s", ip)}
}

func (h *IPConnLimitHandler) OnPacket(_ *Context, _ []byte, _ Direction) Result {
	return Result{Action: Continue}
}

func (h *IPConnLimitHandler) OnDisconnect(ctx *Context) {
	rawIP, ok := ctx.Get("_connlimit_ip")
	if !ok {
		return
	}
	ip, _ := rawIP.(string)

	val, ok := h.entries.Load(ip)
	if !ok {
		return
	}
	entry := val.(*ipConnEntry)

	entry.mu.Lock()
	defer entry.mu.Unlock()

	entry.active.Add(-1)

	// Return burst token if this connection was consuming one.
	rawBurst, _ := ctx.Get("_connlimit_burst")
	if wasBurst, _ := rawBurst.(bool); wasBurst {
		entry.burst.Add(-1)
	}
}

func (h *IPConnLimitHandler) getOrCreate(ip string) *ipConnEntry {
	val, _ := h.entries.LoadOrStore(ip, &ipConnEntry{})
	return val.(*ipConnEntry)
}

// ActiveConns returns the number of currently active connections for the given IP.
// Intended for testing and observability.
func (h *IPConnLimitHandler) ActiveConns(ip string) int64 {
	val, ok := h.entries.Load(ip)
	if !ok {
		return 0
	}
	return val.(*ipConnEntry).active.Load()
}
