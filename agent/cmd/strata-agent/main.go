// Command strata-agent runs next to NGINX: it receives worker events on
// strata_event_socket and pushes them to the control plane.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/strata/strata/agent/internal/agent"
)

func main() {
	var cfg agent.Config
	flag.StringVar(&cfg.EventSocket, "event-socket", "unix:/run/strata/events.sock", "event socket (strata_event_socket)")
	flag.StringVar(&cfg.SpoolDir, "spool-dir", "/var/lib/strata/spool", "directory for unacked event batches")
	flag.Int64Var(&cfg.SpoolMaxBytes, "spool-max-bytes", 2<<30, "spool size cap; the oldest batches are dropped beyond it")
	flag.StringVar(&cfg.Server, "server", "", "control plane host:port")
	flag.StringVar(&cfg.ServerName, "server-name", "", "TLS name of the control plane (default: host of -server)")
	flag.StringVar(&cfg.CAFile, "tls-ca", "", "CA bundle trusted for the control plane")
	flag.StringVar(&cfg.CertFile, "tls-cert", "", "client certificate")
	flag.StringVar(&cfg.KeyFile, "tls-key", "", "client certificate key")
	flag.StringVar(&cfg.NodeID, "node-id", "", "node id stamped on every event")
	flag.StringVar(&cfg.MetricsFile, "metrics-file", "/dev/shm/strata/metrics", "counters written by the NGINX workers")
	flag.StringVar(&cfg.MetricsAddr, "metrics-addr", "127.0.0.1:9469", "address of the Prometheus endpoint /metrics")
	flag.Parse()
	cfg.EventSocket = strings.TrimPrefix(cfg.EventSocket, "unix:")

	if err := run(cfg); err != nil {
		fmt.Fprintln(os.Stderr, "strata-agent:", err)
		os.Exit(1)
	}
}

func run(cfg agent.Config) error {
	if cfg.Server == "" || cfg.NodeID == "" {
		return fmt.Errorf("-server and -node-id are required")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	a, err := agent.New(cfg)
	if err != nil {
		return err
	}
	slog.Info("strata-agent started", "socket", cfg.EventSocket, "server", cfg.Server, "spool", cfg.SpoolDir)
	runErr := a.Run(ctx)
	if err := a.Close(); err != nil && runErr == nil {
		runErr = err
	}
	return runErr
}
