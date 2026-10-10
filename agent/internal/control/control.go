// Package control keeps the agent's long-lived FleetService.Connect stream
// (Hello, then a heartbeat every 15 s) and renews the node certificate when
// a third of its lifetime is left (nginx-module.md › "Giao thức gRPC agent
// ↔ control plane").
package control

import (
	"context"
	"errors"
	"log/slog"
	"math/rand/v2"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	fleetv1 "github.com/strata/strata/agent/gen/strata/fleet/v1"
	"github.com/strata/strata/agent/internal/enroll"
	"github.com/strata/strata/agent/internal/identity"
)

// Options configures a controller.
type Options struct {
	Heartbeat  time.Duration // default 15 s
	BackoffMin time.Duration // default 1 s
	BackoffMax time.Duration // default 60 s
	Node       *fleetv1.NodeInfo
	// Counters, when set, fills each heartbeat.
	Counters func() *fleetv1.NodeCounters
	// BundleVersion is the active bundle version reported in Hello and
	// heartbeats.
	BundleVersion func() uint64
	// Identity, when set, is renewed in time; without it the certificate
	// comes from files the agent does not manage.
	Identity *identity.Identity
}

// Controller runs the control stream and the renewal.
type Controller struct {
	client fleetv1.FleetServiceClient
	opts   Options
}

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
	return &Controller{client: client, opts: opts}
}

// Run returns when ctx is done.
func (c *Controller) Run(ctx context.Context) error {
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
	if err := st.Send(&fleetv1.AgentMessage{Msg: &fleetv1.AgentMessage_Hello{Hello: &fleetv1.Hello{
		Node: c.opts.Node, ActiveBundleVersion: c.opts.BundleVersion(),
	}}}); err != nil {
		return recvErr(st, err)
	}
	slog.Info("control stream open")
	recv := make(chan error, 1)
	go func() {
		for {
			m, err := st.Recv()
			if err != nil {
				recv <- err
				return
			}
			// BundleAvailable and commands are handled from W05-G1-01.
			slog.Info("control message", "type", typeName(m))
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
		case <-tick.C:
			hb := &fleetv1.Heartbeat{ActiveBundleVersion: c.opts.BundleVersion()}
			if c.opts.Counters != nil {
				hb.Counters = c.opts.Counters()
			}
			if err := st.Send(&fleetv1.AgentMessage{Msg: &fleetv1.AgentMessage_Heartbeat{Heartbeat: hb}}); err != nil {
				return recvErr(st, err)
			}
		}
	}
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
