package handler

import (
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"
)

func init() {
	Register("ip-ratelimit", NewIPRateLimitHandler)
}

type ipBucket struct {
	tokens    float64
	lastRefil time.Time
	mu        sync.Mutex
}

// IPRateLimitHandler limits concurrent connections per IP using token bucket.
type IPRateLimitHandler struct {
	maxConnsPerIP float64
	refillRate    float64 // tokens per second
	buckets       sync.Map
	stopCleanup   chan struct{}
}

type ipRateLimitConfig struct {
	MaxConnsPerIP int `json:"max_conns_per_ip"`
	RefillPerSec  int `json:"refill_per_sec"`
}

func NewIPRateLimitHandler(raw json.RawMessage) (Handler, error) {
	cfg := ipRateLimitConfig{
		MaxConnsPerIP: 10,
		RefillPerSec:  1,
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return nil, fmt.Errorf("invalid ip-ratelimit config: %w", err)
		}
	}
	if cfg.MaxConnsPerIP <= 0 {
		return nil, fmt.Errorf("max_conns_per_ip must be greater than 0")
	}
	if cfg.RefillPerSec <= 0 {
		cfg.RefillPerSec = 1
	}

	h := &IPRateLimitHandler{
		maxConnsPerIP: float64(cfg.MaxConnsPerIP),
		refillRate:    float64(cfg.RefillPerSec),
		stopCleanup:   make(chan struct{}),
	}

	go h.cleanupLoop()
	return h, nil
}

func (h *IPRateLimitHandler) Name() string {
	return "ip-ratelimit"
}

func (h *IPRateLimitHandler) OnConnect(ctx *Context) Result {
	ip := ctx.ClientAddr.IP.String()

	val, _ := h.buckets.LoadOrStore(ip, &ipBucket{
		tokens:    h.maxConnsPerIP,
		lastRefil: time.Now(),
	})
	bucket := val.(*ipBucket)

	bucket.mu.Lock()
	defer bucket.mu.Unlock()

	// Refill tokens based on elapsed time
	now := time.Now()
	elapsed := now.Sub(bucket.lastRefil).Seconds()
	bucket.tokens += elapsed * h.refillRate
	if bucket.tokens > h.maxConnsPerIP {
		bucket.tokens = h.maxConnsPerIP
	}
	bucket.lastRefil = now

	if bucket.tokens < 1 {
		log.Printf("[ip-ratelimit] rate limited: ip=%s", ip)
		return Result{Action: Drop, Error: fmt.Errorf("rate limit exceeded for ip %s", ip)}
	}

	bucket.tokens--
	return Result{Action: Continue}
}

func (h *IPRateLimitHandler) OnPacket(_ *Context, _ []byte, _ Direction) Result {
	return Result{Action: Continue}
}

func (h *IPRateLimitHandler) OnDisconnect(_ *Context) {}

// cleanupLoop removes stale buckets every 60 seconds to prevent memory leaks.
func (h *IPRateLimitHandler) cleanupLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-h.stopCleanup:
			return
		case <-ticker.C:
			now := time.Now()
			h.buckets.Range(func(key, value any) bool {
				bucket := value.(*ipBucket)
				bucket.mu.Lock()
				idle := now.Sub(bucket.lastRefil)
				bucket.mu.Unlock()
				if idle > 5*time.Minute {
					h.buckets.Delete(key)
				}
				return true
			})
		}
	}
}
