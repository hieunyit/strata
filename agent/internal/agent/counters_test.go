package agent

import (
	"testing"

	fleetv1 "github.com/strata/strata/agent/gen/strata/fleet/v1"
	"github.com/strata/strata/agent/internal/shmmetrics"
)

// W12-G2-01: the heartbeat carries the workers' totals and their canary
// groups; a module without canary counters leaves them out.
func TestFillCounters(t *testing.T) {
	lat := func(first uint64) []uint64 { return []uint64{first, 0, 0, 0, 0, 0, 0, 0, 1} }
	snap := shmmetrics.Snapshot{CreatedMs: 1760000000000, Workers: []shmmetrics.Worker{
		{Requests: [4]uint64{90, 5, 0, 5}, FailOpen: 1, HasCanary: true, Canary: [2]shmmetrics.CanaryGroup{
			{Requests: 10, Blocked: 4, Upstream5xx: 1, Latency: lat(9)}, {Requests: 90, Logged: 3, Latency: lat(89)}}},
		{Requests: [4]uint64{10, 0, 0, 0}, HasCanary: true, Canary: [2]shmmetrics.CanaryGroup{
			{Requests: 2, Latency: lat(1)}, {Requests: 8, Upstream5xx: 2, Latency: lat(7)}}},
	}}
	nc := &fleetv1.NodeCounters{}
	fillCounters(nc, snap)
	if nc.Requests != 110 || nc.Blocked != 5 || nc.FailOpen != 1 || nc.MetricsCreatedMs != 1760000000000 {
		t.Fatalf("totals %+v", nc)
	}
	c, s := nc.GetCanary(), nc.GetCanaryShadow()
	if c.GetRequests() != 12 || c.GetBlocked() != 4 || c.GetUpstreamServerErrors() != 1 || c.GetLatency()[0] != 10 || c.GetLatency()[8] != 2 ||
		s.GetRequests() != 98 || s.GetLogged() != 3 || s.GetUpstreamServerErrors() != 2 {
		t.Fatalf("canary %v shadow %v", c, s)
	}
	old := &fleetv1.NodeCounters{}
	fillCounters(old, shmmetrics.Snapshot{Workers: []shmmetrics.Worker{{Requests: [4]uint64{1, 0, 0, 0}}}})
	if old.Canary != nil || old.CanaryShadow != nil || old.Requests != 1 {
		t.Fatalf("older module: %+v", old)
	}
}

// W20-F-01: the engine time histogram and total, summed over the workers.
func TestFillCountersEngineTime(t *testing.T) {
	nc := &fleetv1.NodeCounters{}
	fillCounters(nc, shmmetrics.Snapshot{Workers: []shmmetrics.Worker{
		{EngineNanos: 1000, EngineBuckets: []uint64{5, 3, 0, 0, 0, 0, 0, 0, 1}},
		{EngineNanos: 500, EngineBuckets: []uint64{1, 0, 0, 0, 0, 0, 0, 2, 0}},
	}})
	want := []uint64{6, 3, 0, 0, 0, 0, 0, 2, 1}
	if len(nc.EngineTime) != len(want) || nc.EngineNs != 1500 {
		t.Fatalf("engine time %v %d", nc.EngineTime, nc.EngineNs)
	}
	for i := range want {
		if nc.EngineTime[i] != want[i] {
			t.Fatalf("engine time %v, want %v", nc.EngineTime, want)
		}
	}
}
