package standalone

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	eventv1 "github.com/strata/strata/agent/gen/strata/event/v1"
	"github.com/strata/strata/agent/internal/eventsock"
	"github.com/strata/strata/agent/internal/shmmetrics"
)

// Config configures the standalone runner.
type Config struct {
	Standalone         bool
	EventSocket        string        // unix socket: /run/strata/events.sock
	ControlFile        string        // /run/strata/control
	BundleFile         string        // e.g. /var/lib/strata/bundles/bundle.sbn
	BundleDir          string        // e.g. /var/lib/strata/bundles
	BundleURL          string        // optional static HTTP URL
	BundlePollInterval time.Duration // default 2s
	BundlePubKey       string        // /etc/strata/bundle.pub
	EventsJSONL        string        // /var/log/strata/events.jsonl
	SyslogAddr         string        // 127.0.0.1:514 or unixgram:/dev/log
	SyslogTag          string        // strata-waf
	MetricsFile        string        // /dev/shm/strata/metrics
	MetricsAddr        string        // 127.0.0.1:9469
	NodeID             string        // defaults to hostname
	AgentVersion       string
}

// Runner coordinates standalone agent execution.
type Runner struct {
	cfg      Config
	socket   *eventsock.Listener
	watcher  *BundleWatcher
	exporter *EventExporter
	registry *prometheus.Registry
}

// New creates a new standalone runner.
func New(cfg Config) (*Runner, error) {
	cfg.EventSocket = strings.TrimPrefix(cfg.EventSocket, "unix:")
	if cfg.NodeID == "" {
		cfg.NodeID, _ = os.Hostname()
		if cfg.NodeID == "" {
			cfg.NodeID = "standalone-node"
		}
	}

	exporter, err := NewEventExporter(cfg.EventsJSONL, cfg.SyslogAddr, cfg.SyslogTag)
	if err != nil {
		return nil, fmt.Errorf("standalone: init exporter: %w", err)
	}

	watcher, err := NewBundleWatcher(
		cfg.BundleFile,
		cfg.BundleDir,
		cfg.BundleURL,
		cfg.ControlFile,
		cfg.BundlePubKey,
		cfg.BundlePollInterval,
	)
	if err != nil {
		_ = exporter.Close()
		return nil, fmt.Errorf("standalone: init bundle watcher: %w", err)
	}

	sock, err := eventsock.Listen(cfg.EventSocket)
	if err != nil {
		_ = exporter.Close()
		return nil, fmt.Errorf("standalone: listen event socket: %w", err)
	}

	reg := prometheus.NewRegistry()

	r := &Runner{
		cfg:      cfg,
		socket:   sock,
		watcher:  watcher,
		exporter: exporter,
		registry: reg,
	}

	// Link runner to collector
	reg.MustRegister(&runnerMetrics{r: r})

	if cfg.MetricsFile != "" {
		reg.MustRegister(shmmetrics.NewCollector(cfg.MetricsFile))
	}

	return r, nil
}

// Run starts the standalone agent services and blocks until ctx is canceled.
func (r *Runner) Run(parent context.Context) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	var services sync.WaitGroup
	slog.Info("strata-agent running in standalone mode",
		"event_socket", r.cfg.EventSocket,
		"control_file", r.cfg.ControlFile,
		"bundle_dir", r.cfg.BundleDir,
		"events_jsonl", r.cfg.EventsJSONL,
		"metrics_addr", r.cfg.MetricsAddr,
	)

	errCh := make(chan error, 3)

	// 1. Bundle watcher goroutine
	services.Add(1)
	go func() {
		defer services.Done()
		if err := r.watcher.Run(ctx); err != nil && ctx.Err() == nil {
			errCh <- fmt.Errorf("bundle watcher: %w", err)
		}
	}()

	// 2. Event listener goroutine
	services.Add(1)
	go func() {
		defer services.Done()
		err := r.socket.Run(ctx, func(ev *eventv1.Event) {
			ev.NodeId = r.cfg.NodeID
			if err := r.exporter.Export(ev); err != nil {
				slog.Debug("standalone: export event error", "err", err)
			}
		})
		if err != nil && ctx.Err() == nil {
			errCh <- fmt.Errorf("event socket: %w", err)
		}
	}()

	// 3. Prometheus metrics HTTP server
	if r.cfg.MetricsAddr != "" {
		services.Add(1)
		go func() {
			defer services.Done()
			if err := shmmetrics.Serve(ctx, r.cfg.MetricsAddr, r.registry); err != nil && ctx.Err() == nil {
				errCh <- fmt.Errorf("metrics server: %w", err)
			}
		}()
	}

	var runErr error
	select {
	case <-ctx.Done():
		slog.Info("standalone: stopping agent on context cancellation")
	case err := <-errCh:
		slog.Error("standalone: service error encountered", "err", err)
		runErr = err
	}

	// Stop every producer and join before closing the exporter used by callbacks.
	cancel()
	services.Wait()
	return errors.Join(runErr, r.socket.Close(), r.exporter.Close())
}

type runnerMetrics struct {
	r *Runner
}

func (m *runnerMetrics) Describe(ch chan<- *prometheus.Desc) {
	ch <- descReceived
	ch <- descExported
	ch <- descDropped
	ch <- descBundleVersion
}

func (m *runnerMetrics) Collect(ch chan<- prometheus.Metric) {
	rx := m.r.socket.C.Received.Load()
	exp, drp := m.r.exporter.Stats()
	ver := m.r.watcher.Active()

	ch <- prometheus.MustNewConstMetric(descReceived, prometheus.CounterValue, float64(rx))
	ch <- prometheus.MustNewConstMetric(descExported, prometheus.CounterValue, float64(exp))
	ch <- prometheus.MustNewConstMetric(descDropped, prometheus.CounterValue, float64(drp))
	ch <- prometheus.MustNewConstMetric(descBundleVersion, prometheus.GaugeValue, float64(ver))
}

var (
	descReceived      = prometheus.NewDesc("strata_agent_standalone_events_received_total", "Total events received on socket.", nil, nil)
	descExported      = prometheus.NewDesc("strata_agent_standalone_events_exported_total", "Total events exported to JSONL or Syslog.", nil, nil)
	descDropped       = prometheus.NewDesc("strata_agent_standalone_events_dropped_total", "Total events dropped by exporter.", nil, nil)
	descBundleVersion = prometheus.NewDesc("strata_agent_bundle_active_version", "Currently active bundle version.", nil, nil)
)
