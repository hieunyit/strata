package agent

import (
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/strata/strata/agent/internal/fallback"
	"github.com/strata/strata/agent/internal/fleettest"
	"github.com/strata/strata/agent/internal/pusher"
)

func TestAgentMetrics(t *testing.T) {
	srv, certs := fleettest.NewServer(t)
	cfg := testConfig(t, srv, certs, pusher.Options{BackoffMin: 50 * time.Millisecond, BackoffMax: time.Second})
	r := start(t, cfg)
	w := newWorker(t, cfg.EventSocket)
	w.send(5)
	if _, err := w.conn.Write([]byte{0xff}); err != nil {
		t.Fatal(err)
	}
	waitDelivered(t, srv, 5, 10*time.Second)
	deadline := time.Now().Add(5 * time.Second)
	for r.a.Socket.C.Invalid.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	// the server has the events before the agent reads its ack
	for st := r.a.Spool.Stats(); st.LastSeq != st.AckedSeq && time.Now().Before(deadline); st = r.a.Spool.Stats() {
		time.Sleep(10 * time.Millisecond)
	}

	want := `
# HELP strata_agent_events_received_total Datagrams read from the event socket.
# TYPE strata_agent_events_received_total counter
strata_agent_events_received_total 6
# HELP strata_agent_events_invalid_total Datagrams that did not decode or lacked a Block ID.
# TYPE strata_agent_events_invalid_total counter
strata_agent_events_invalid_total 1
# HELP strata_agent_spool_unacked_batches Batches spooled but not acked by the control plane.
# TYPE strata_agent_spool_unacked_batches gauge
strata_agent_spool_unacked_batches 0
`
	if err := testutil.GatherAndCompare(r.a.Registry, strings.NewReader(want),
		"strata_agent_events_received_total", "strata_agent_events_invalid_total",
		"strata_agent_spool_unacked_batches"); err != nil {
		t.Fatal(err)
	}
	// Exercise the collector with fallback enabled without changing the running agent.
	c := collector{a: &Agent{Socket: r.a.Socket, Pusher: r.a.Pusher, Spool: r.a.Spool,
		Fallback: fallback.NewWatcher("", nil, fallback.Options{})}}
	if err := testutil.CollectAndCompare(c, strings.NewReader(`
# HELP strata_agent_fallback_alerts_total Source saturation or jumps of engine errors or budget overruns that left the policies as they are, by reason.
# TYPE strata_agent_fallback_alerts_total counter
strata_agent_fallback_alerts_total{reason="source_limit"} 0
strata_agent_fallback_alerts_total{reason="engine_errors"} 0
strata_agent_fallback_alerts_total{reason="budget"} 0
`), "strata_agent_fallback_alerts_total"); err != nil {
		t.Fatal(err)
	}
	mfs, err := r.a.Registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]float64{}
	for _, mf := range mfs {
		if m := mf.GetMetric(); len(m) == 1 && m[0].GetGauge() != nil {
			got[mf.GetName()] = m[0].GetGauge().GetValue()
		}
	}
	// fleettest has no Connect: the stream never opens (the open case is
	// tested in internal/control).
	if v, ok := got["strata_agent_control_connected"]; !ok || v != 0 {
		t.Errorf("control_connected = %v (present %v), want 0", v, ok)
	}
	if _, ok := got["strata_agent_unix_max_dgram_qlen"]; !ok {
		t.Error("unix_max_dgram_qlen missing")
	}
	if r.a.identity != nil && got["strata_agent_cert_not_after_seconds"] < float64(time.Now().Unix()) {
		t.Errorf("cert_not_after_seconds = %v, not in the future", got["strata_agent_cert_not_after_seconds"])
	}
	if problems, err := testutil.GatherAndLint(r.a.Registry); err != nil || len(problems) != 0 {
		t.Fatalf("lint: %v %+v", err, problems)
	}
	if err := r.stop(); err != nil {
		t.Fatal(err)
	}
}
