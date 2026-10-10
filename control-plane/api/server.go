package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/strata/strata/control-plane/ingest"
)

// ServerConfig defines HTTP server configuration options.
type ServerConfig struct {
	Addr         string
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}

// Server provides the REST API server for Strata control plane.
type Server struct {
	cfg        ServerConfig
	httpServer *http.Server
	handler    *EventHandler
	mux        *http.ServeMux
}

// NewServer initializes the HTTP router and server with middleware.
func NewServer(cfg ServerConfig, store ingest.EventStore) *Server {
	if cfg.Addr == "" {
		cfg.Addr = ":8080"
	}
	if cfg.ReadTimeout <= 0 {
		cfg.ReadTimeout = 10 * time.Second
	}
	if cfg.WriteTimeout <= 0 {
		cfg.WriteTimeout = 10 * time.Second
	}

	eventHandler := NewEventHandler(store)
	mux := http.NewServeMux()

	s := &Server{
		cfg:     cfg,
		handler: eventHandler,
		mux:     mux,
	}

	s.registerRoutes()

	s.httpServer = &http.Server{
		Addr:         cfg.Addr,
		Handler:      s.withMiddleware(mux),
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
	}

	return s
}

// Handler returns the underlying http.Handler (useful for httptest).
func (s *Server) Handler() http.Handler {
	return s.withMiddleware(s.mux)
}

func (s *Server) registerRoutes() {
	s.mux.HandleFunc("/v1/events:search", s.handler.HandleSearchEvents)

	// Handles /v1/events/{block_id}
	s.mux.HandleFunc("/v1/events/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ":search") {
			s.handler.HandleSearchEvents(w, r)
			return
		}
		s.handler.HandleGetEvent(w, r)
	})
}

func (s *Server) withMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				writeError(w, http.StatusInternalServerError, fmt.Sprintf("internal server panic: %v", rec), "")
			}
		}()

		// Request timeout
		ctx, cancel := context.WithTimeout(r.Context(), s.cfg.WriteTimeout)
		defer cancel()

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Start begins listening and serving HTTP requests.
func (s *Server) Start() error {
	return s.httpServer.ListenAndServe()
}

// Shutdown gracefully shuts down the server without interrupting active connections.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}
