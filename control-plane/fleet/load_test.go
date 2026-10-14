package fleet

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	fleetv1 "github.com/strata/strata/agent/gen/strata/fleet/v1"
	"github.com/strata/strata/control-plane/store"
)

// W08-G1-01: 1000 simulated agents hold a Connect stream, and a
// BundleAvailable broadcast reaches all 1000 in under 10 seconds.
func TestFleetLoad1000Agents(t *testing.T) {
	if testing.Short() {
		t.Skip("load test: 1000 gRPC streams")
	}
	const n = 1000
	const deadline = 10 * time.Second

	p := newPKI(t)
	reg := newMemRegistry()
	srv := NewServer(Config{Ingest: nopIngest{}, Registry: reg, Presence: NewPresence()})
	addr := serveServer(t, p, srv)

	// One enrolled node, certificate and client per agent, built on the test
	// goroutine because the dial/cert helpers call t.Fatal.
	ids := make([]string, n)
	clients := make([]fleetv1.FleetServiceClient, n)
	for i := range n {
		id := fmt.Sprintf("node-%04d", i)
		ids[i] = id
		cert := p.nodeCert(t, id)
		reg.nodes[id] = store.Node{ID: id, CertSerial: leafSerial(t, cert)}
		// desired == the version Hello reports (1), so Hello sends no
		// BundleAvailable: the only one an agent sees is the broadcast.
		reg.desired[id] = store.Bundle{Version: 1, SHA256: make([]byte, 32), SizeBytes: 1}
		clients[i] = dial(t, p, addr, &cert)
	}

	var connected, got int64
	recvAt := make([]time.Time, n)
	errc := make(chan error, n)
	var wg sync.WaitGroup

	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			st, err := clients[i].Connect(ctx)
			if err != nil {
				errc <- fmt.Errorf("%s connect: %w", ids[i], err)
				return
			}
			if err := st.Send(&fleetv1.AgentMessage{Msg: &fleetv1.AgentMessage_Hello{Hello: &fleetv1.Hello{
				Node: &fleetv1.NodeInfo{Hostname: ids[i]}, ActiveBundleVersion: 1,
			}}}); err != nil {
				errc <- fmt.Errorf("%s hello: %w", ids[i], err)
				return
			}
			atomic.AddInt64(&connected, 1)
			// blocks here until the broadcast, since desired == active
			for {
				m, err := st.Recv()
				if err != nil {
					errc <- fmt.Errorf("%s recv: %w", ids[i], err)
					return
				}
				if m.GetBundleAvailable().GetVersion() == 2 {
					recvAt[i] = time.Now()
					atomic.AddInt64(&got, 1)
					return
				}
			}
		}(i)
	}

	// Every agent is connected and stable before the broadcast.
	waitFor(t, 30*time.Second, "1000 agents connected", func() bool {
		return atomic.LoadInt64(&connected) == n && len(srv.Presence().ConnectedNodes()) == n
	})
	select {
	case err := <-errc:
		t.Fatalf("an agent failed before the broadcast: %v", err)
	default:
	}

	// Broadcast a new bundle to every node, as a rollout's notify does.
	t0 := time.Now()
	for _, id := range ids {
		srv.Presence().Notify(id, BundleAvailable(store.Bundle{Version: 2, SHA256: make([]byte, 32)}, false))
	}

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case err := <-errc:
		t.Fatalf("agent error: %v", err)
	case <-time.After(deadline + 20*time.Second):
		t.Fatalf("only %d/%d agents received the broadcast", atomic.LoadInt64(&got), n)
	}

	if got != n {
		t.Fatalf("received %d/%d", got, n)
	}
	var max time.Duration
	for _, at := range recvAt {
		if d := at.Sub(t0); d > max {
			max = d
		}
	}
	t.Logf("BundleAvailable reached %d/%d agents, slowest %v", got, n, max)
	if max > deadline {
		t.Fatalf("slowest delivery %v exceeds %v", max, deadline)
	}
}

func waitFor(t *testing.T, d time.Duration, what string, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !f() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// W12-G1-02: a DisableRules command for each of 1000 connected nodes, sent
// by the command dispatcher, reaches every node in under 10 seconds.
func TestKillSwitchReaches1000Agents(t *testing.T) {
	if testing.Short() {
		t.Skip("load test: 1000 gRPC streams")
	}
	const n = 1000
	const deadline = 10 * time.Second

	p := newPKI(t)
	reg := newMemRegistry()
	srv := NewServer(Config{Ingest: nopIngest{}, Registry: reg, Presence: NewPresence()})
	addr := serveServer(t, p, srv)
	ids := make([]string, n)
	clients := make([]fleetv1.FleetServiceClient, n)
	for i := range n {
		id := fmt.Sprintf("node-%04d", i)
		ids[i] = id
		cert := p.nodeCert(t, id)
		reg.nodes[id] = store.Node{ID: id, CertSerial: leafSerial(t, cert)}
		reg.desired[id] = store.Bundle{Version: 1, SHA256: make([]byte, 32), SizeBytes: 1}
		clients[i] = dial(t, p, addr, &cert)
	}

	var connected, got int64
	recvAt := make([]time.Time, n)
	errc := make(chan error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			st, err := clients[i].Connect(ctx)
			if err != nil {
				errc <- fmt.Errorf("%s connect: %w", ids[i], err)
				return
			}
			if err := st.Send(&fleetv1.AgentMessage{Msg: &fleetv1.AgentMessage_Hello{Hello: &fleetv1.Hello{
				Node: &fleetv1.NodeInfo{Hostname: ids[i]}, ActiveBundleVersion: 1,
			}}}); err != nil {
				errc <- fmt.Errorf("%s hello: %w", ids[i], err)
				return
			}
			atomic.AddInt64(&connected, 1)
			for {
				m, err := st.Recv()
				if err != nil {
					errc <- fmt.Errorf("%s recv: %w", ids[i], err)
					return
				}
				if d := m.GetCommand().GetDisableRules(); d != nil {
					if len(d.GetRuleIds()) != 1 || d.GetRuleIds()[0] != 942100 || d.GetReplace() {
						errc <- fmt.Errorf("%s: %v", ids[i], d)
						return
					}
					recvAt[i] = time.Now()
					atomic.AddInt64(&got, 1)
					return
				}
			}
		}(i)
	}
	waitFor(t, 30*time.Second, "1000 agents connected", func() bool {
		return atomic.LoadInt64(&connected) == n && len(srv.Presence().ConnectedNodes()) == n
	})

	// what POST /v1/rules/942100:emergencyDisable stores: one command per node
	t0 := time.Now()
	reg.mu.Lock()
	for i, id := range ids {
		reg.commands = append(reg.commands, store.Command{ID: fmt.Sprintf("ks-%04d", i), NodeID: id,
			Kind: store.CommandDisableRules, RuleIDs: []int32{942100}, State: store.CommandPending, ExpiresAt: t0.Add(time.Hour)})
	}
	reg.mu.Unlock()
	cmds := NewCommands(reg, srv.Presence())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go cmds.Run(ctx)
	cmds.Kick()

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case err := <-errc:
		t.Fatalf("agent error: %v", err)
	case <-time.After(deadline + 20*time.Second):
		t.Fatalf("only %d/%d agents received the command", atomic.LoadInt64(&got), n)
	}
	var max time.Duration
	for _, at := range recvAt {
		if d := at.Sub(t0); d > max {
			max = d
		}
	}
	t.Logf("DisableRules reached %d/%d agents, slowest %v", got, n, max)
	if max > deadline {
		t.Fatalf("slowest delivery %v exceeds %v", max, deadline)
	}
}
