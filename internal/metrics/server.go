package metrics

import (
	"encoding/json"
	"log"
	"net/http"
	"sync/atomic"
	"time"
)

var startTime = time.Now()

// SessionInfo represents a single session for the /sessions endpoint.
type SessionInfo struct {
	SNI         string  `json:"sni"`
	Backend     string  `json:"backend"`
	ClientAddr  string  `json:"client_addr"`
	Username    string  `json:"username,omitempty"`
	PlayerUUID  string  `json:"player_uuid,omitempty"`
	BytesIn     int64   `json:"bytes_in"`
	BytesOut    int64   `json:"bytes_out"`
	IdleSecs    float64 `json:"idle_secs"`
	ConnectedAt string  `json:"connected_at"`
}

// Provider is implemented by the proxy to expose live data to the metrics server.
type Provider interface {
	SessionCount() int
	Sessions() []SessionInfo
	TotalBytesIn() int64
	TotalBytesOut() int64
}

// Server is the metrics HTTP server.
type Server struct {
	listen   string
	provider Provider
	totalIn  atomic.Int64
	totalOut atomic.Int64
}

// New creates a new metrics server.
func New(listen string, provider Provider) *Server {
	return &Server{
		listen:   listen,
		provider: provider,
	}
}

// Start starts the metrics HTTP server in a goroutine.
func (s *Server) Start() {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/metrics", s.handleMetrics)
	mux.HandleFunc("/sessions", s.handleSessions)

	srv := &http.Server{
		Addr:         s.listen,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}

	go func() {
		log.Printf("[metrics] listening on %s", s.listen)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[metrics] server error: %v", err)
		}
	}()
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status": "ok",
		"uptime": time.Since(startTime).Round(time.Second).String(),
	})
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	data := map[string]any{
		"uptime":          time.Since(startTime).Round(time.Second).String(),
		"sessions_active": s.provider.SessionCount(),
		"bytes_in_total":  s.provider.TotalBytesIn(),
		"bytes_out_total": s.provider.TotalBytesOut(),
	}

	json.NewEncoder(w).Encode(data)
}

func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	sessions := s.provider.Sessions()
	if sessions == nil {
		sessions = []SessionInfo{}
	}
	json.NewEncoder(w).Encode(sessions)
}
