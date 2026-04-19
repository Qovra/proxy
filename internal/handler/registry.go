package handler

import (
	"encoding/json"
	"fmt"
)

// HandlerConfig represents a handler configuration entry.
type HandlerConfig struct {
	Type   string          `json:"type"`
	Config json.RawMessage `json:"config,omitempty"`
}

// Factory is a function that creates a Handler from config.
type Factory func(config json.RawMessage) (Handler, error)

var registry = map[string]Factory{}

// Register registers a handler factory by name.
func Register(name string, factory Factory) {
	registry[name] = factory
}

// BuildChain builds a handler chain from a list of configs.
func BuildChain(configs []HandlerConfig) (*Chain, error) {
	handlers := make([]Handler, 0, len(configs))
	for _, cfg := range configs {
		factory, ok := registry[cfg.Type]
		if !ok {
			return nil, fmt.Errorf("unknown handler type: %q", cfg.Type)
		}
		h, err := factory(cfg.Config)
		if err != nil {
			return nil, fmt.Errorf("failed to create handler %q: %w", cfg.Type, err)
		}
		handlers = append(handlers, h)
	}
	return NewChain(handlers...), nil
}
