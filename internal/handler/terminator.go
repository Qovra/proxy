package handler

import (
	"encoding/json"
	"errors"
	"log"
)

func init() {
	Register("terminator", NewTerminatorHandler)
}

// TerminatorConfig holds TLS config for the terminator handler.
type TerminatorConfig struct {
	Listen string                 `json:"listen"`
	Certs  *TerminatorCertsConfig `json:"certs,omitempty"`
	Debug  bool                   `json:"debug"`
}

// TerminatorCertsConfig groups certificate configurations.
type TerminatorCertsConfig struct {
	Default *TerminatorCertConfig            `json:"default"`
	Targets map[string]*TerminatorCertConfig `json:"targets,omitempty"`
}

// TerminatorCertConfig holds TLS cert/key paths.
type TerminatorCertConfig struct {
	Cert        string `json:"cert"`
	Key         string `json:"key"`
	BackendMTLS *bool  `json:"backend_mtls,omitempty"`
}

// TerminatorHandler handles TLS termination for protocol inspection.
// When no external terminator library is available, it acts as a passthrough
// and logs a warning. Full TLS termination requires the terminator submodule.
type TerminatorHandler struct {
	cfg TerminatorConfig
}

func NewTerminatorHandler(raw json.RawMessage) (Handler, error) {
	var cfg TerminatorConfig
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return nil, err
		}
	}
	if cfg.Listen == "" {
		cfg.Listen = ":5521"
	}
	log.Printf("[terminator] initialized (listen=%s)", cfg.Listen)
	return &TerminatorHandler{cfg: cfg}, nil
}

func (h *TerminatorHandler) Name() string {
	return "terminator"
}

func (h *TerminatorHandler) OnConnect(ctx *Context) Result {
	backend := ctx.GetString("backend")
	if backend == "" {
		return Result{Action: Drop, Error: errors.New("no backend")}
	}
	log.Printf("[terminator] connection from %s -> %s", ctx.ClientAddr, backend)
	return Result{Action: Continue}
}

func (h *TerminatorHandler) OnPacket(_ *Context, _ []byte, _ Direction) Result {
	return Result{Action: Continue}
}

func (h *TerminatorHandler) OnDisconnect(_ *Context) {}
