// Package control keeps the agent's long-lived FleetService.Connect stream
// (Hello, then a heartbeat every 15 s) and renews the node certificate when
// a third of its lifetime is left (nginx-module.md › "Giao thức gRPC agent
// ↔ control plane").
package control

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	fleetv1 "github.com/strata/strata/agent/gen/strata/fleet/v1"
	"github.com/strata/strata/agent/internal/enroll"
	"github.com/strata/strata/agent/internal/identity"
)

// Options configures a controller.
type Options struct {
	Capabilities func(*fleetv1.Connector) []string
	Heartbeat    time.Duration // default 15 s
	BackoffMin   time.Duration // default 1 s
	BackoffMax   time.Duration // default 60 s
	Node         *fleetv1.NodeInfo
	// Connector, when set, gives the proxy and module versions sent in
	// Hello; when they change (the module started, or was upgraded), the
	// stream is opened again so the control plane learns them.
	Connector func() *fleetv1.Connector
	// Counters, when set, fills each heartbeat.
	Counters func() *fleetv1.NodeCounters
	Health   func() *fleetv1.AgentHealth
	// BundleVersion is the active bundle version reported in Hello and
	// heartbeats.
	BundleVersion func() uint64
	// Identity, when set, is renewed in time; without it the certificate
	// comes from files the agent does not manage.
	Identity *identity.Identity
	// OnBundle receives each BundleAvailable (bundles.Manager.Offer).
	OnBundle func(context.Context, *fleetv1.BundleAvailable)
	// OnCommand runs a Command; its result goes back on the stream. Without
	// it every command is answered "not supported".
	OnCommand func(context.Context, *fleetv1.Command) *fleetv1.CommandResult
	// OnRenewed runs after the certificate was renewed: connections made
	// with the old one must be closed, since the control plane refuses
	// new calls on them ("certificate superseded").
	OnRenewed func()
}

// Controller runs the control stream and the renewal.
type Controller struct {
	client fleetv1.FleetServiceClient
	opts   Options
	runCtx context.Context

	statuses chan *fleetv1.BundleStatus
	results  chan *fleetv1.CommandResult
	mu       sync.Mutex
	last     *fleetv1.BundleStatus // sent again after a reconnect
	up       atomic.Bool           // a stream is open (Hello sent)
}

// Connected reports whether the control stream is open.
func (c *Controller) Connected() bool { return c.up.Load() }

// New returns a controller.
func New(client fleetv1.FleetServiceClient, opts Options) *Controller {
	if opts.Heartbeat <= 0 {
		opts.Heartbeat = 15 * time.Second
	}
	if opts.BackoffMin <= 0 {
		opts.BackoffMin = time.Second
	}
	if opts.BackoffMax < opts.BackoffMin {
		opts.BackoffMax = 60 * time.Second
	}
	if opts.BundleVersion == nil {
		opts.BundleVersion = func() uint64 { return 0 }
	}
	return &Controller{client: client, opts: opts, statuses: make(chan *fleetv1.BundleStatus, 64),
		results: make(chan *fleetv1.CommandResult, 16), runCtx: context.Background()}
}

// Report queues a bundle status for the control plane. The latest one is
// also sent after every reconnect, so a status reported while the stream
// was down is not lost.
func (c *Controller) Report(bs *fleetv1.BundleStatus) {
	c.mu.Lock()
	c.last = bs
	c.mu.Unlock()
	select {
	case c.statuses <- bs:
	default: // full: the latest one goes out after the next Hello
	}
}

// Run returns when ctx is done.
func (c *Controller) Run(ctx context.Context) error {
	c.runCtx = ctx
	done := make(chan struct{})
	if c.opts.Identity != nil {
		go func() { defer close(done); c.renewLoop(ctx) }()
	} else {
		close(done)
	}
	c.connectLoop(ctx)
	<-done
	return nil
}

func (c *Controller) sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// jitter spreads reconnects of many nodes: a random time in [d/2, d].
func jitter(d time.Duration) time.Duration {
	return d/2 + time.Duration(rand.Int64N(int64(d/2)+1))
}

func (c *Controller) connectLoop(ctx context.Context) {
	backoff := c.opts.BackoffMin
	for ctx.Err() == nil {
		start := time.Now()
		err := c.stream(ctx)
		if ctx.Err() != nil {
			return
		}
		switch status.Code(err) {
		case codes.Unimplemented:
			slog.Warn("control plane has no Connect; control stream disabled")
			<-ctx.Done()
			return
		case codes.PermissionDenied, codes.Unauthenticated:
			slog.Error("control plane refused this node; re-enroll if it was revoked", "err", err)
			backoff = c.opts.BackoffMax
		default:
			slog.Warn("control stream ended", "err", err)
		}
		if time.Since(start) > 2*c.opts.Heartbeat {
			backoff = c.opts.BackoffMin // it had been up: start over
		}
		if !c.sleep(ctx, jitter(backoff)) {
			return
		}
		backoff = min(2*backoff, c.opts.BackoffMax)
	}
}

func (c *Controller) stream(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	st, err := c.client.Connect(ctx)
	if err != nil {
		return err
	}
	node, sent := c.node()
	if err := st.Send(&fleetv1.AgentMessage{Msg: &fleetv1.AgentMessage_Hello{Hello: &fleetv1.Hello{
		Node: node, ActiveBundleVersion: c.opts.BundleVersion(),
	}}}); err != nil {
		return recvErr(st, err)
	}
	slog.Info("control stream open")
	c.up.Store(true)
	defer c.up.Store(false)
	c.mu.Lock()
	last := c.last
	c.mu.Unlock()
	if last != nil {
		if err := st.Send(&fleetv1.AgentMessage{Msg: &fleetv1.AgentMessage_BundleStatus{BundleStatus: last}}); err != nil {
			return recvErr(st, err)
		}
	}
	recv := make(chan error, 1)
	go func() {
		for {
			m, err := st.Recv()
			if err != nil {
				recv <- err
				return
			}
			switch msg := m.GetMsg().(type) {
			case *fleetv1.ControlMessage_BundleAvailable:
				slog.Info("bundle available", "version", msg.BundleAvailable.GetVersion())
				if c.opts.OnBundle != nil {
					// The agent's context: an install outlives a stream.
					c.opts.OnBundle(c.runCtx, msg.BundleAvailable)
				}
			case *fleetv1.ControlMessage_Command:
				c.command(msg.Command)
			default:
				slog.Info("control message", "type", typeName(m))
			}
		}
	}()
	tick := time.NewTicker(c.opts.Heartbeat)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-recv:
			return err
		case r := <-c.results:
			if err := st.Send(&fleetv1.AgentMessage{Msg: &fleetv1.AgentMessage_CommandResult{CommandResult: r}}); err != nil {
				return recvErr(st, err)
			}
		case bs := <-c.statuses:
			if err := st.Send(&fleetv1.AgentMessage{Msg: &fleetv1.AgentMessage_BundleStatus{BundleStatus: bs}}); err != nil {
				return recvErr(st, err)
			}
		case <-tick.C:
			if _, now := c.node(); now != sent {
				slog.Info("connector versions changed; reconnecting to report them", "versions", now)
				return nil
			}
			node, _ := c.node()
			hb := &fleetv1.Heartbeat{ActiveBundleVersion: c.opts.BundleVersion(), Node: node}
			if c.opts.Health != nil {
				hb.Health = c.opts.Health()
			}
			if c.opts.Counters != nil {
				hb.Counters = c.opts.Counters()
			}
			if err := st.Send(&fleetv1.AgentMessage{Msg: &fleetv1.AgentMessage_Heartbeat{Heartbeat: hb}}); err != nil {
				return recvErr(st, err)
			}
		}
	}
}

// command runs cmd off the receive loop and queues its result. A result
// lost with the stream is not sent again: the control plane expires the
// command, and the operator sends it again.
func (c *Controller) command(cmd *fleetv1.Command) {
	slog.Info("command", "id", cmd.GetId(), "action", actionName(cmd))
	go func() {
		var r *fleetv1.CommandResult
		if c.opts.OnCommand != nil {
			r = c.opts.OnCommand(c.runCtx, cmd)
		}
		if r == nil {
			r = &fleetv1.CommandResult{Error: "not supported"}
		}
		r.CommandId = cmd.GetId()
		if !r.GetOk() {
			slog.Warn("command failed", "id", cmd.GetId(), "err", r.GetError())
		}
		select {
		case c.results <- r:
		case <-c.runCtx.Done():
		}
	}()
}

func actionName(cmd *fleetv1.Command) string {
	switch cmd.GetAction().(type) {
	case *fleetv1.Command_ForceShadow:
		return "force_shadow"
	case *fleetv1.Command_Diagnostics:
		return "diagnostics"
	}
	return "unknown"
}

// node is the NodeInfo for Hello, with the connector versions now, and
// those versions as one string to compare.
func (c *Controller) node() (*fleetv1.NodeInfo, string) {
	if c.opts.Connector == nil || c.opts.Node == nil {
		return c.opts.Node, ""
	}
	n := proto.Clone(c.opts.Node).(*fleetv1.NodeInfo)
	cn := c.opts.Connector()
	if cn == nil {
		return n, ""
	}
	if n.Connector == nil {
		n.Connector = &fleetv1.Connector{}
	}
	n.Connector.ProxyVersion, n.Connector.ModuleVersion, n.Connector.AbiVersion = cn.GetProxyVersion(), cn.GetModuleVersion(), cn.GetAbiVersion()
	if c.opts.Capabilities != nil {
		n.Capabilities = c.opts.Capabilities(n.Connector)
	}
	return n, fmt.Sprintf("%s/%s/%#x", cn.GetProxyVersion(), cn.GetModuleVersion(), cn.GetAbiVersion())
}

// recvErr returns the stream's status once Send fails with io.EOF.
func recvErr(st fleetv1.FleetService_ConnectClient, sendErr error) error {
	if _, err := st.Recv(); err != nil {
		return err
	}
	return sendErr
}

func typeName(m *fleetv1.ControlMessage) string {
	switch m.GetMsg().(type) {
	case *fleetv1.ControlMessage_BundleAvailable:
		return "bundle_available"
	case *fleetv1.ControlMessage_Command:
		return "command"
	}
	return "unknown"
}

// renewLoop renews when a third of the lifetime is left, retrying failures
// every minute (at most every 10) until it works.
func (c *Controller) renewLoop(ctx context.Context) {
	retry := time.Minute
	for {
		wait := time.Until(c.opts.Identity.RenewAt())
		if wait > 0 && !c.sleep(ctx, wait) {
			return
		}
		if ctx.Err() != nil {
			return
		}
		if err := c.renew(ctx); err != nil {
			slog.Error("certificate renewal failed", "err", err, "retry_in", retry)
			if !c.sleep(ctx, jitter(retry)) {
				return
			}
			retry = min(2*retry, 10*time.Minute)
			continue
		}
		retry = time.Minute
		leaf := c.opts.Identity.Certificate().Leaf
		slog.Info("node certificate renewed", "serial", leaf.SerialNumber.Text(16), "not_after", leaf.NotAfter)
		if c.opts.OnRenewed != nil {
			c.opts.OnRenewed()
		}
	}
}

func (c *Controller) renew(ctx context.Context) error {
	host := ""
	if c.opts.Node != nil {
		host = c.opts.Node.GetHostname()
	}
	next, err := enroll.NewIdentity(host)
	if err != nil {
		return err
	}
	rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	resp, err := c.client.RenewCertificate(rctx, &fleetv1.RenewRequest{Csr: next.CSRDER})
	if err != nil {
		return err
	}
	keyPEM, err := next.KeyPEM()
	if err != nil {
		return err
	}
	if len(resp.GetCertificate()) == 0 {
		return errors.New("control plane returned no certificate")
	}
	return c.opts.Identity.Replace(keyPEM, resp.GetCertificate())
}
