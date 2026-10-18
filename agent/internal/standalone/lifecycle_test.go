package standalone

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRunnerFailureStopsAndJoinsServices(t *testing.T) {
	d := t.TempDir()
	_, pub, _ := makeTestBundle(1, 1)
	key := filepath.Join(d, "key")
	if err := os.WriteFile(key, pub, 0600); err != nil {
		t.Fatal(err)
	}
	started, stopped := make(chan struct{}), make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
		close(stopped)
	}))
	ctx, cancel := context.WithCancel(context.Background())
	defer srv.Close()
	defer cancel()
	r, err := New(Config{EventSocket: filepath.Join(d, "events.sock"), BundleURL: srv.URL, BundleDir: d, BundlePubKey: key, ControlFile: filepath.Join(d, "control"), EventsJSONL: filepath.Join(d, "events.jsonl")})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("watcher did not start")
	}
	if err := r.socket.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("lost service error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("runner did not stop")
	}
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Error("failed runner left bundle request running")
	}
	r.exporter.mu.Lock()
	closed := r.exporter.file == nil
	r.exporter.mu.Unlock()
	if !closed {
		t.Error("failed runner leaked exporter")
	}
}

func TestRunnerCancellationAndMetricsFailure(t *testing.T) {
	for _, metricsFailure := range []bool{false, true} {
		t.Run(map[bool]string{false: "parent-cancel", true: "metrics-bind-error"}[metricsFailure], func(t *testing.T) {
			d := t.TempDir()
			_, pub, _ := makeTestBundle(1, 1)
			key := filepath.Join(d, "key")
			if err := os.WriteFile(key, pub, 0600); err != nil {
				t.Fatal(err)
			}
			cfg := Config{EventSocket: filepath.Join(d, "events.sock"), BundleDir: d, BundlePubKey: key, ControlFile: filepath.Join(d, "control"), EventsJSONL: filepath.Join(d, "events.jsonl")}
			if metricsFailure {
				ln, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer ln.Close()
				cfg.MetricsAddr = ln.Addr().String()
			}
			r, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if !metricsFailure {
				cancel()
			}
			done := make(chan error, 1)
			go func() { done <- r.Run(ctx) }()
			select {
			case err := <-done:
				if (err != nil) != metricsFailure {
					t.Fatalf("unexpected result: %v", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("runner failed to join services")
			}
			if _, err := os.Stat(cfg.EventSocket); !os.IsNotExist(err) {
				t.Fatalf("socket path remains: %v", err)
			}
			r.exporter.mu.Lock()
			closed := r.exporter.file == nil
			r.exporter.mu.Unlock()
			if !closed {
				t.Fatal("exporter still open")
			}
		})
	}
}
