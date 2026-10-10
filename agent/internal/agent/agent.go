// Package agent wires the event path of strata-agent: event socket ->
// batcher -> spool -> PushEvents.
package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"

	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	eventv1 "github.com/strata/strata/agent/gen/strata/event/v1"
	fleetv1 "github.com/strata/strata/agent/gen/strata/fleet/v1"
	"github.com/strata/strata/agent/internal/batch"
	"github.com/strata/strata/agent/internal/eventsock"
	"github.com/strata/strata/agent/internal/pusher"
	"github.com/strata/strata/agent/internal/shmmetrics"
	"github.com/strata/strata/agent/internal/spool"
)

// Config of the event path.
type Config struct {
	EventSocket   string // strata_event_socket, without the unix: prefix
	SpoolDir      string
	SpoolMaxBytes int64  // default 2 GB
	Server        string // control plane host:port
	ServerName    string // TLS name of the control plane; default: host of Server
	CAFile        string // CA the agent trusts for the control plane
	CertFile      string // client certificate (mTLS)
	KeyFile       string
	NodeID        string
	MetricsFile   string // written by the NGINX module; empty: not exported
	MetricsAddr   string // host:port for /metrics; empty: no exporter

	Batch  batch.Options
	Push   pusher.Options
	noSync bool // tests: skip fsync in the spool
}

// Agent is a running event path.
type Agent struct {
	Socket *eventsock.Listener
	Spool  *spool.Spool
	Pusher *pusher.Pusher
	// Registry holds the agent's metrics and, with MetricsFile, the
	// workers' counters.
	Registry *prometheus.Registry
	conn     *grpc.ClientConn
	batch    *batch.Batcher
	cfg      Config
}

// New opens the spool, binds the event socket and prepares the client.
func New(cfg Config) (*Agent, error) {
	creds, err := clientTLS(cfg)
	if err != nil {
		return nil, err
	}
	sp, err := spool.Open(cfg.SpoolDir, spool.Options{MaxBytes: cfg.SpoolMaxBytes, NoSync: cfg.noSync})
	if err != nil {
		return nil, err
	}
	conn, err := grpc.NewClient(cfg.Server, grpc.WithTransportCredentials(creds))
	if err != nil {
		sp.Close()
		return nil, fmt.Errorf("agent: dial %s: %w", cfg.Server, err)
	}
	sock, err := eventsock.Listen(cfg.EventSocket)
	if err != nil {
		conn.Close()
		sp.Close()
		return nil, err
	}
	cfg.Batch.NodeID = cfg.NodeID
	a := &Agent{
		Socket:   sock,
		Spool:    sp,
		Pusher:   pusher.New(fleetv1.NewFleetServiceClient(conn), sp, cfg.Push),
		Registry: prometheus.NewRegistry(),
		conn:     conn,
		batch:    batch.New(sp, cfg.Batch),
		cfg:      cfg,
	}
	a.Registry.MustRegister(collector{a})
	if cfg.MetricsFile != "" {
		a.Registry.MustRegister(shmmetrics.NewCollector(cfg.MetricsFile))
	}
	return a, nil
}

// Run serves until ctx is done. On the way out it stops reading the
// socket first, then flushes the pending batch into the spool, so that a
// clean restart loses nothing; unacked batches are sent after restart.
func (a *Agent) Run(ctx context.Context) error {
	sockCtx, stopSock := context.WithCancel(ctx)
	defer stopSock()
	batchCtx, stopBatch := context.WithCancel(context.Background())
	defer stopBatch()
	pushCtx, stopPush := context.WithCancel(ctx)
	defer stopPush()

	sockDone := make(chan error, 1)
	batchDone := make(chan error, 1)
	pushDone := make(chan error, 1)
	go func() {
		sockDone <- a.Socket.Run(sockCtx, func(ev *eventv1.Event) { a.batch.Add(batchCtx, ev) })
	}()
	go func() { batchDone <- a.batch.Run(batchCtx) }()
	go func() { pushDone <- a.Pusher.Run(pushCtx) }()
	metricsDone := make(chan error, 1)
	if a.cfg.MetricsAddr != "" {
		go func() { metricsDone <- shmmetrics.Serve(pushCtx, a.cfg.MetricsAddr, a.Registry) }()
	}

	var errs []error
	select {
	case <-ctx.Done():
	case err := <-sockDone:
		errs, sockDone = append(errs, err), nil
	case err := <-batchDone:
		errs, batchDone = append(errs, err), nil
	case err := <-pushDone:
		errs, pushDone = append(errs, err), nil
	case err := <-metricsDone:
		errs = append(errs, err)
	}
	stopSock()
	if sockDone != nil {
		errs = append(errs, <-sockDone)
	}
	stopBatch()
	if batchDone != nil {
		errs = append(errs, <-batchDone)
	}
	stopPush()
	if pushDone != nil {
		errs = append(errs, <-pushDone)
	}
	return errors.Join(errs...)
}

// Close releases the socket, the connection and the spool.
func (a *Agent) Close() error {
	return errors.Join(a.Socket.Close(), a.conn.Close(), a.Spool.Close())
}

func clientTLS(cfg Config) (credentials.TransportCredentials, error) {
	if cfg.CAFile == "" || cfg.CertFile == "" || cfg.KeyFile == "" {
		return nil, errors.New("agent: mTLS needs a CA, a client certificate and its key")
	}
	pair, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("agent: client certificate: %w", err)
	}
	pem, err := os.ReadFile(cfg.CAFile)
	if err != nil {
		return nil, fmt.Errorf("agent: read CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("agent: no certificate in %s", cfg.CAFile)
	}
	return credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{pair},
		RootCAs:      pool,
		ServerName:   cfg.ServerName,
		MinVersion:   tls.VersionTLS13,
	}), nil
}
