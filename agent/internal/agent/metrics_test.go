package agent

import (
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

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
	if problems, err := testutil.GatherAndLint(r.a.Registry); err != nil || len(problems) != 0 {
		t.Fatalf("lint: %v %+v", err, problems)
	}
	if err := r.stop(); err != nil {
		t.Fatal(err)
	}
}
