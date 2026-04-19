package proxy

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/Qovra/core/internal/handler"
)

// Config represents the proxy configuration.
type Config struct {
	Listen         string                  `json:"listen"`
	Handlers       []handler.HandlerConfig `json:"handlers"`
	SessionTimeout int                     `json:"session_timeout,omitempty"`
	MetricsListen  string                  `json:"metrics_listen,omitempty"`
}

// Validate checks that all required fields are present and valid.
func (c *Config) Validate() error {
	if c.Listen == "" {
		return fmt.Errorf("listen address is required")
	}
	if len(c.Handlers) == 0 {
		return fmt.Errorf("at least one handler is required")
	}
	for i, h := range c.Handlers {
		if h.Type == "" {
			return fmt.Errorf("handler[%d] is missing type", i)
		}
	}
	return nil
}

// LoadConfig loads configuration from a JSON file.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}
	return ParseConfig(data)
}

// ParseConfig parses configuration from JSON bytes.
func ParseConfig(data []byte) (*Config, error) {
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	return &cfg, nil
}
