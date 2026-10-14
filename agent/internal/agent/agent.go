// Package agent wires the event path of strata-agent: event socket ->
// batcher -> spool -> PushEvents.
package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"

	eventv1 "github.com/strata/strata/agent/gen/strata/event/v1"
	fleetv1 "github.com/strata/strata/agent/gen/strata/fleet/v1"
	"github.com/strata/strata/agent/internal/batch"
	"github.com/strata/strata/agent/internal/bundles"
	"github.com/strata/strata/agent/internal/control"
	"github.com/strata/strata/agent/internal/enroll"
	"github.com/strata/strata/agent/internal/eventsock"
	"github.com/strata/strata/agent/internal/fallback"
	"github.com/strata/strata/agent/internal/forceshadow"
	"github.com/strata/strata/agent/internal/identity"
	"github.com/strata/strata/agent/internal/killswitch"
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
	// IdentityDir, when set, replaces CAFile, CertFile, KeyFile and NodeID
	// with the enrolled identity, renewed in time.
	IdentityDir string
	// BundleDir and ControlFile, when set, make the agent install the
	// bundles the control plane rolls out; BundlePubKey verifies them
	// (default: bundle.pub of the identity directory).
	BundleDir    string
	ControlFile  string
	BundlePubKey string
	AgentVersion string
	MetricsFile  string // written by the NGINX module; empty: not exported
	MetricsAddr  string // host:port for /metrics; empty: no exporter
	// Fallback runs the node tier of the automatic fallback (needs
	// BundleDir and MetricsFile).
	Fallback        bool
	FallbackOptions fallback.Options

	Batch  batch.Options
	Push   pusher.Options
	noSync bool // tests: skip fsync in the spool
}

// Agent is a running event path.
type Agent struct {
	Socket *eventsock.Listener
	Spool  *spool.Spool
	Pusher *pusher.Pusher
	// Control keeps the Connect stream and renews the certificate.
	Control *control.Controller
	// Bundles installs rolled-out bundles; nil without BundleDir.
	Bundles *bundles.Manager
	// ForceShadow applies ForceShadow commands; nil without BundleDir.
	ForceShadow *forceshadow.Manager
	// Fallback forces the node into shadow on its own; nil when off.
	Fallback *fallback.Watcher
	// KillSwitch applies DisableRules and EnableRules; nil without BundleDir.
	KillSwitch *killswitch.Manager
	// Registry holds the agent's metrics and, with MetricsFile, the
	// workers' counters.
	Registry *prometheus.Registry
	conn     *grpc.ClientConn
	conns    *connTracker
	batch    *batch.Batcher
	cfg      Config
	started  time.Time
	identity *identity.Identity
	// dgramQlen is net.unix.max_dgram_qlen read at start (0: unknown).
	dgramQlen int
}

// New opens the spool, binds the event socket and prepares the client.
func New(cfg Config) (*Agent, error) {
	var id *identity.Identity
	if cfg.IdentityDir != "" {
		var err error
		if id, err = identity.Load(cfg.IdentityDir); err != nil {
			return nil, err
		}
		cfg.NodeID = id.NodeID
	}
	creds, err := clientTLS(cfg, id)
	if err != nil {
		return nil, err
	}
	sp, err := spool.Open(cfg.SpoolDir, spool.Options{MaxBytes: cfg.SpoolMaxBytes, NoSync: cfg.noSync})
	if err != nil {
		return nil, err
	}
	conns := &connTracker{}
	conn, err := grpc.NewClient(cfg.Server, grpc.WithTransportCredentials(creds), grpc.WithContextDialer(conns.dial),
		// The control plane pings every 10 s; answer, and ping too.
		grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: 20 * time.Second, Timeout: 10 * time.Second, PermitWithoutStream: true}),
		// gRPC's own redial backoff grows to 120 s by default: after a long
		// outage the agent would stay away up to two minutes past its own
		// retry. 30 s at most, with jitter.
		grpc.WithConnectParams(grpc.ConnectParams{Backoff: backoff.Config{
			BaseDelay: time.Second, Multiplier: 1.6, Jitter: 0.2, MaxDelay: 30 * time.Second,
		}, MinConnectTimeout: 10 * time.Second}))
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
	host, _ := os.Hostname()
	client := fleetv1.NewFleetServiceClient(conn)
	a := &Agent{
		Socket:   sock,
		Spool:    sp,
		Pusher:   pusher.New(client, sp, cfg.Push),
		Registry: prometheus.NewRegistry(),
		conn:     conn,
		conns:    conns,
		batch:    batch.New(sp, cfg.Batch),
		cfg:      cfg,
		started:  time.Now(),
		identity: id,
	}
	a.dgramQlen = checkDgramQlen(procDgramQlen)
	var bm *bundles.Manager
	ctrl := &control.Controller{}
	if cfg.BundleDir != "" {
		pubFile := cfg.BundlePubKey
		if pubFile == "" && cfg.IdentityDir != "" {
			pubFile = filepath.Join(cfg.IdentityDir, enroll.BundleKeyFile)
		}
		pub, err := os.ReadFile(pubFile)
		if err != nil {
			conn.Close()
			sp.Close()
			sock.Close()
			return nil, fmt.Errorf("agent: bundle public key: %w", err)
		}
		bm, err = bundles.New(client, bundles.Options{
			Dir: cfg.BundleDir, ControlFile: cfg.ControlFile, PubKey: pub, MetricsFile: cfg.MetricsFile,
		}, func(bs *fleetv1.BundleStatus) { ctrl.Report(bs) })
		if err != nil {
			conn.Close()
			sp.Close()
			sock.Close()
			return nil, err
		}
	}
	if bm != nil {
		a.ForceShadow = forceshadow.New(cfg.ControlFile, filepath.Join(cfg.BundleDir, "force-shadow.json"))
		a.KillSwitch = killswitch.New(cfg.ControlFile, filepath.Join(cfg.BundleDir, "disabled-rules.json"))
		if cfg.Fallback && cfg.MetricsFile != "" {
			a.Fallback = fallback.NewWatcher(cfg.MetricsFile, a.ForceShadow, cfg.FallbackOptions)
		}
	}
	copts := control.Options{
		Identity:  id,
		OnCommand: a.command,
		OnRenewed: func() {
			// Calls on the old connections would be refused as superseded.
			slog.Info("closing connections made with the old certificate", "conns", conns.closeAll())
		},
		Node: &fleetv1.NodeInfo{Hostname: host, AgentVersion: cfg.AgentVersion, Connector: &fleetv1.Connector{Type: "nginx"}},
		Counters: func() *fleetv1.NodeCounters {
			st := sp.Stats()
			return &fleetv1.NodeCounters{DroppedEvents: st.DroppedEvents}
		},
	}
	if cfg.MetricsFile != "" {
		copts.Connector = func() *fleetv1.Connector {
			snap, err := shmmetrics.Read(cfg.MetricsFile)
			if err != nil {
				return nil
			}
			return &fleetv1.Connector{ProxyVersion: snap.ProxyVersion, ModuleVersion: snap.ModuleVersion, AbiVersion: snap.ABIVersion}
		}
	}
	if bm != nil {
		copts.BundleVersion = bm.Active
		copts.OnBundle = bm.Offer
	}
	*ctrl = *control.New(client, copts)
	a.Control = ctrl
	a.Bundles = bm
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
	controlDone := make(chan error, 1)
	go func() { controlDone <- a.Control.Run(pushCtx) }()
	fsDone := make(chan struct{})
	if a.ForceShadow != nil {
		go func() { a.ForceShadow.Run(pushCtx); close(fsDone) }()
	} else {
		close(fsDone)
	}
	ksDone := make(chan struct{})
	if a.KillSwitch != nil {
		go func() { a.KillSwitch.Run(pushCtx); close(ksDone) }()
	} else {
		close(ksDone)
	}
	fbDone := make(chan struct{})
	if a.Fallback != nil {
		go func() { a.Fallback.Run(pushCtx); close(fbDone) }()
	} else {
		close(fbDone)
	}
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
	errs = append(errs, <-controlDone)
	<-fsDone
	<-fbDone
	<-ksDone
	return errors.Join(errs...)
}

// Close releases the socket, the connection and the spool.
func (a *Agent) Close() error {
	return errors.Join(a.Socket.Close(), a.conn.Close(), a.Spool.Close())
}

func clientTLS(cfg Config, id *identity.Identity) (credentials.TransportCredentials, error) {
	if id != nil {
		return credentials.NewTLS(&tls.Config{
			GetClientCertificate: id.GetClientCertificate,
			RootCAs:              id.CAPool,
			ServerName:           cfg.ServerName,
			MinVersion:           tls.VersionTLS13,
		}), nil
	}
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
