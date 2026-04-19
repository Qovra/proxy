package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"

	"github.com/Qovra/core/internal/backend"
)

func init() {
	Register("sni-router", NewSNIRouterHandler)
}

// SNIRouterHandler routes connections based on SNI hostname to a backend pool.
// Each SNI may have one or more backends; selection is round-robin with
// automatic skipping of backends currently marked unhealthy.
type SNIRouterHandler struct {
	routes map[string]*backend.Pool
}

func NewSNIRouterHandler(raw json.RawMessage) (Handler, error) {
	var cfg struct {
		Routes map[string]any `json:"routes"`
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return nil, fmt.Errorf("invalid sni-router config: %w", err)
		}
	}
	if len(cfg.Routes) == 0 {
		return nil, fmt.Errorf("sni-router requires 'routes' config")
	}

	routes := make(map[string]*backend.Pool, len(cfg.Routes))
	for sni, val := range cfg.Routes {
		addresses, err := parseBackendList(sni, val)
		if err != nil {
			return nil, err
		}
		routes[sni] = backend.NewPool(addresses)
		log.Printf("[sni-router] SNI=%q → %d backend(s): %v", sni, len(addresses), addresses)
	}

	return &SNIRouterHandler{routes: routes}, nil
}

func (h *SNIRouterHandler) Name() string { return "sni-router" }

func (h *SNIRouterHandler) OnConnect(ctx *Context) Result {
	if ctx.Hello == nil {
		return Result{Action: Drop, Error: errors.New("no ClientHello")}
	}
	sni := ctx.Hello.SNI
	if sni == "" {
		return Result{Action: Drop, Error: errors.New("no SNI")}
	}

	pool, ok := h.routes[sni]
	if !ok {
		return Result{Action: Drop, Error: fmt.Errorf("unknown SNI: %s", sni)}
	}

	addr, ok := pool.Next()
	if !ok {
		log.Printf("[sni-router] all backends unhealthy for SNI=%s — dropping connection from %s",
			sni, ctx.ClientAddr)
		return Result{Action: Drop, Error: fmt.Errorf("all backends unhealthy for SNI %s", sni)}
	}

	ctx.Set("backend", addr)
	return Result{Action: Continue}
}

func (h *SNIRouterHandler) OnPacket(_ *Context, _ []byte, _ Direction) Result {
	return Result{Action: Continue}
}

func (h *SNIRouterHandler) OnDisconnect(_ *Context) {}

// Stop terminates all backend health-check goroutines managed by this handler.
// Should be called when the handler is being replaced (e.g. on config reload).
func (h *SNIRouterHandler) Stop() {
	for _, pool := range h.routes {
		pool.Stop()
	}
}

// Status returns the health state of all backends across all routes.
// Keyed by SNI hostname.
func (h *SNIRouterHandler) Status() map[string][]backend.BackendStatus {
	out := make(map[string][]backend.BackendStatus, len(h.routes))
	for sni, pool := range h.routes {
		out[sni] = pool.Status()
	}
	return out
}

// parseBackendList normalises a config value into a slice of address strings.
// Accepts either a single string or a JSON array of strings.
func parseBackendList(sni string, val any) ([]string, error) {
	switch v := val.(type) {
	case string:
		return []string{v}, nil
	case []any:
		if len(v) == 0 {
			return nil, fmt.Errorf("empty backends for SNI %s", sni)
		}
		addrs := make([]string, len(v))
		for i, b := range v {
			s, ok := b.(string)
			if !ok {
				return nil, fmt.Errorf("invalid backend for SNI %s at index %d: expected string", sni, i)
			}
			addrs[i] = s
		}
		return addrs, nil
	default:
		return nil, fmt.Errorf("invalid backend for SNI %s: expected string or array", sni)
	}
}
