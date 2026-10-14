package agent

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"runtime"
	"sync"
	"time"

	fleetv1 "github.com/strata/strata/agent/gen/strata/fleet/v1"
	"github.com/strata/strata/agent/internal/bundles"
	"github.com/strata/strata/agent/internal/forceshadow"
	"github.com/strata/strata/agent/internal/shmmetrics"
)

// command runs a Command of the control plane.
func (a *Agent) command(_ context.Context, cmd *fleetv1.Command) *fleetv1.CommandResult {
	switch act := cmd.GetAction().(type) {
	case *fleetv1.Command_ForceShadow:
		if a.ForceShadow == nil {
			return &fleetv1.CommandResult{Error: "this agent installs no bundles (no --bundle-dir)"}
		}
		if err := a.ForceShadow.Apply(act.ForceShadow); err != nil {
			return &fleetv1.CommandResult{Error: err.Error()}
		}
		return &fleetv1.CommandResult{Ok: true}
	case *fleetv1.Command_DisableRules:
		if a.KillSwitch == nil {
			return &fleetv1.CommandResult{Error: "this agent installs no bundles (no --bundle-dir)"}
		}
		if err := a.KillSwitch.Disable(act.DisableRules); err != nil {
			return &fleetv1.CommandResult{Error: err.Error()}
		}
		return &fleetv1.CommandResult{Ok: true}
	case *fleetv1.Command_EnableRules:
		if a.KillSwitch == nil {
			return &fleetv1.CommandResult{Error: "this agent installs no bundles (no --bundle-dir)"}
		}
		if err := a.KillSwitch.Enable(act.EnableRules); err != nil {
			return &fleetv1.CommandResult{Error: err.Error()}
		}
		return &fleetv1.CommandResult{Ok: true}
	case *fleetv1.Command_ReplaySampling:
		if a.Replay == nil {
			return &fleetv1.CommandResult{Error: "this agent installs no bundles (no --bundle-dir)"}
		}
		if err := a.Replay.Apply(act.ReplaySampling); err != nil {
			return &fleetv1.CommandResult{Error: err.Error()}
		}
		return &fleetv1.CommandResult{Ok: true}
	case *fleetv1.Command_Diagnostics:
		b, err := json.Marshal(a.diagnostics())
		if err != nil {
			return &fleetv1.CommandResult{Error: err.Error()}
		}
		return &fleetv1.CommandResult{Ok: true, Output: string(b)}
	}
	return &fleetv1.CommandResult{Error: "not supported"}
}

// Diagnostics is what CollectDiagnostics returns: versions, the bundle,
// counters. Never keys, certificates, tokens, configuration files or
// paths outside what the operator configured.
type Diagnostics struct {
	AgentVersion  string           `json:"agent_version"`
	GoVersion     string           `json:"go_version"`
	NodeID        string           `json:"node_id"`
	Hostname      string           `json:"hostname"`
	UptimeSeconds int64            `json:"uptime_seconds"`
	Bundle        *DiagBundle      `json:"bundle,omitempty"`
	ForceShadow   *DiagForceShadow `json:"force_shadow,omitempty"`
	DisabledRules []uint32         `json:"disabled_rules,omitempty"`
	Replay        *DiagReplay      `json:"replay_sampling,omitempty"`
	Spool         DiagSpool        `json:"spool"`
	Workers       []DiagWorker     `json:"workers,omitempty"`
	MetricsError  string           `json:"metrics_error,omitempty"`
}

// DiagBundle: the control file and the bundle reported active.
type DiagBundle struct {
	Active     uint64 `json:"active"`
	Control    string `json:"control_file_bundle,omitempty"`
	Version    uint64 `json:"control_file_version"`
	Generation uint64 `json:"control_file_generation"`
	// sha256 prefixes of the trusted bundle signing keys (key rotation)
	TrustedKeys []string `json:"trusted_keys"`
	Error       string   `json:"error,omitempty"`
}

// DiagForceShadow: the deadlines still running.
type DiagForceShadow struct {
	AllUntil *time.Time           `json:"all_until,omitempty"`
	Policies map[string]time.Time `json:"policies,omitempty"`
	// Fallback: the node fallback holds every policy (W12-G1-01).
	Fallback *forceshadow.Hold `json:"fallback,omitempty"`
}

// DiagReplay: the replay sampling in force (never the key).
type DiagReplay struct {
	RateBp uint32 `json:"rate_bp"`
	KeyID  string `json:"key_id,omitempty"`
}

// DiagSpool: the event spool.
type DiagSpool struct {
	Bytes          int64  `json:"bytes"`
	Segments       int    `json:"segments"`
	Unacked        uint64 `json:"unacked_batches"`
	DroppedBatches uint64 `json:"dropped_batches"`
	DroppedEvents  uint64 `json:"dropped_events"`
}

// DiagWorker: one NGINX worker's slot of the metrics file.
type DiagWorker struct {
	PID           uint64    `json:"pid"`
	BundleVersion uint64    `json:"bundle_version"`
	Requests      [4]uint64 `json:"requests"` // allow, log, challenge, block
	FailOpen      uint64    `json:"fail_open"`
	FailClosed    uint64    `json:"fail_closed"`
	EventsDropped uint64    `json:"events_dropped"`
	BudgetExceed  uint64    `json:"budget_exceeded"`
}

func (a *Agent) diagnostics() Diagnostics {
	host, _ := os.Hostname()
	st := a.Spool.Stats()
	d := Diagnostics{
		AgentVersion: a.cfg.AgentVersion, GoVersion: runtime.Version(), NodeID: a.cfg.NodeID, Hostname: host,
		UptimeSeconds: int64(time.Since(a.started) / time.Second),
		Spool: DiagSpool{Bytes: st.Bytes, Segments: st.Segments, Unacked: st.LastSeq - st.AckedSeq,
			DroppedBatches: st.DroppedBatches, DroppedEvents: st.DroppedEvents},
	}
	if a.Bundles != nil {
		b := &DiagBundle{Active: a.Bundles.Active(), TrustedKeys: a.Bundles.TrustedKeys()}
		if c, err := bundles.ReadControl(a.cfg.ControlFile); err != nil {
			b.Error = "control file: not readable"
		} else {
			b.Control, b.Version, b.Generation = c.Name, c.Version, c.Generation
		}
		d.Bundle = b
	}
	if a.ForceShadow != nil {
		s := a.ForceShadow.Snapshot()
		fs := &DiagForceShadow{Policies: s.Policies, Fallback: s.Fallback}
		if !s.All.IsZero() {
			fs.AllUntil = &s.All
		}
		d.ForceShadow = fs
	}
	if a.Replay != nil {
		if s := a.Replay.Current(); s != nil {
			d.Replay = &DiagReplay{RateBp: s.Rate, KeyID: s.KeyID}
		}
	}
	if a.KillSwitch != nil {
		d.DisabledRules = a.KillSwitch.Rules()
	}
	if a.cfg.MetricsFile != "" {
		snap, err := shmmetrics.Read(a.cfg.MetricsFile)
		if err != nil {
			d.MetricsError = "metrics file: not readable"
		}
		for _, w := range snap.Workers {
			d.Workers = append(d.Workers, DiagWorker{PID: w.PID, BundleVersion: w.BundleVersion, Requests: w.Requests,
				FailOpen: w.FailOpen, FailClosed: w.FailClosed, EventsDropped: w.EventsDropped, BudgetExceed: w.BudgetExceed})
		}
	}
	return d
}

// connTracker remembers the connections gRPC dials, so that they can be
// closed after a certificate renewal: gRPC then dials again and the TLS
// handshake presents the new certificate.
type connTracker struct {
	mu    sync.Mutex
	conns map[net.Conn]struct{}
}

func (t *connTracker) dial(ctx context.Context, addr string) (net.Conn, error) {
	c, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	tc := &trackedConn{Conn: c, t: t}
	t.mu.Lock()
	if t.conns == nil {
		t.conns = map[net.Conn]struct{}{}
	}
	t.conns[tc] = struct{}{}
	t.mu.Unlock()
	return tc, nil
}

// closeAll closes every connection dialed so far.
func (t *connTracker) closeAll() int {
	t.mu.Lock()
	conns := t.conns
	t.conns = nil
	t.mu.Unlock()
	for c := range conns {
		_ = c.(*trackedConn).Conn.Close()
	}
	return len(conns)
}

type trackedConn struct {
	net.Conn
	t *connTracker
}

func (c *trackedConn) Close() error {
	c.t.mu.Lock()
	delete(c.t.conns, c)
	c.t.mu.Unlock()
	return c.Conn.Close()
}
