package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/strata/strata/control-plane/api"
	"github.com/strata/strata/control-plane/ingest"
)

func main() {
	addr := flag.String("addr", ":8080", "Server listen address")
	inMemory := flag.Bool("in-memory", true, "Use in-memory store instead of ClickHouse")
	chAddr := flag.String("clickhouse-addr", "127.0.0.1:9000", "ClickHouse native protocol address")
	seed := flag.Bool("seed", true, "Seed sample events into memory store")
	flag.Parse()

	var store ingest.EventStore

	if *inMemory {
		log.Println("[INFO] Initializing in-memory EventStore")
		memStore := ingest.NewMockEventStore()
		if *seed {
			seedDemoEvents(memStore)
		}
		store = memStore
	} else {
		log.Printf("[INFO] Connecting to ClickHouse at %s\n", *chAddr)
		chStore, err := ingest.NewClickHouseStore(context.Background(), ingest.ClickHouseConfig{
			Addr:     *chAddr,
			Database: "default",
			Table:    "events",
		})
		if err != nil {
			log.Fatalf("[FATAL] Failed to connect to ClickHouse: %v", err)
		}
		defer chStore.Close()
		store = chStore
	}

	srv := api.NewServer(api.ServerConfig{
		Addr:         *addr,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}, store)

	// Wrap with restricted CORS middleware for lab UI origins
	allowedOrigins := map[string]bool{
		"http://localhost:3000": true,
		"http://127.0.0.1:3000": true,
		"http://localhost:5173": true,
		"http://127.0.0.1:5173": true,
		"http://localhost:8080": true,
		"http://127.0.0.1:8080": true,
	}

	handlerWithCORS := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if allowedOrigins[origin] {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		srv.Handler().ServeHTTP(w, r)
	})

	server := &http.Server{
		Addr:         *addr,
		Handler:      handlerWithCORS,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	go func() {
		log.Printf("[INFO] Control Plane Event API listening on %s\n", *addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[FATAL] Server error: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	log.Println("[INFO] Shutting down server gracefully...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Printf("[ERROR] Server forced to shutdown: %v\n", err)
	}
	log.Println("[INFO] Server stopped")
}

func seedDemoEvents(store *ingest.MockEventStore) {
	now := time.Now().UTC()
	events := []ingest.Event{
		{
			BlockID:       "STR-8F3K-Q2VD-7XNM-A1PC",
			Timestamp:     now.Add(-2 * time.Minute),
			NodeID:        "edge-worker-01",
			ConnectorType: "nginx",
			PolicyID:      "example-api",
			PolicyVersion: 1,
			ClientIP:      "198.51.100.42",
			Identity:      "anon-client-1",
			RequestID:     "req-001-sqli-attempt",
			HTTPMethod:    "POST",
			HTTPHost:      "api.example.test",
			HTTPPath:      "/v1/users/search",
			StatusCode:    403,
			Action:        "block",
			ScoreProtocol: 0,
			ScoreSQLi:     45,
			ScoreXSS:      0,
			ScoreAnomaly:  45,
			MatchedRules:  []uint32{942100, 942150},
			Violations: []ingest.Violation{
				{
					RuleID:  942100,
					Layer:   "sqli",
					Field:   "body.query",
					Snippet: "' OR 1=1 --",
				},
				{
					RuleID:  942150,
					Layer:   "sqli",
					Field:   "body.query",
					Snippet: "UNION SELECT null, username, password FROM users",
				},
			},
			ReceivedAt: now.Add(-2 * time.Minute),
		},
		{
			BlockID:       "STR-3B9Y-K8P2-WM4C-9D0R",
			Timestamp:     now.Add(-10 * time.Minute),
			NodeID:        "edge-worker-02",
			ConnectorType: "nginx",
			PolicyID:      "example-api",
			PolicyVersion: 1,
			ClientIP:      "203.0.113.19",
			Identity:      "guest-browser",
			RequestID:     "req-002-xss-attempt",
			HTTPMethod:    "GET",
			HTTPHost:      "api.example.test",
			HTTPPath:      "/comments",
			StatusCode:    403,
			Action:        "block",
			ScoreProtocol: 0,
			ScoreSQLi:     0,
			ScoreXSS:      30,
			ScoreAnomaly:  30,
			MatchedRules:  []uint32{941100},
			Violations: []ingest.Violation{
				{
					RuleID:  941100,
					Layer:   "xss",
					Field:   "uri.query.text",
					Snippet: "<script>alert(document.cookie)</script>",
				},
			},
			ReceivedAt: now.Add(-10 * time.Minute),
		},
		{
			BlockID:       "EVT-7X2W-5M1Q-9H8K-L0P4",
			Timestamp:     now.Add(-30 * time.Minute),
			NodeID:        "edge-worker-01",
			ConnectorType: "nginx",
			PolicyID:      "example-api",
			PolicyVersion: 1,
			ClientIP:      "192.0.2.77",
			Identity:      "scanner-bot",
			RequestID:     "req-003-shadow-probe",
			HTTPMethod:    "GET",
			HTTPHost:      "api.example.test",
			HTTPPath:      "/.env",
			StatusCode:    200,
			Action:        "shadow",
			ScoreProtocol: 15,
			ScoreSQLi:     0,
			ScoreXSS:      0,
			ScoreAnomaly:  15,
			MatchedRules:  []uint32{100005},
			Violations: []ingest.Violation{
				{
					RuleID:  100005,
					Layer:   "protocol",
					Field:   "uri.path",
					Snippet: "/.env",
				},
			},
			ReceivedAt: now.Add(-30 * time.Minute),
		},
	}

	_ = store.SaveEvents(context.Background(), events)
	log.Printf("[INFO] Pre-seeded %d demo events into memory store\n", len(events))
}
