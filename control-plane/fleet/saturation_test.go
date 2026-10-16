package fleet

import (
	"testing"
	"time"

	eventv1 "github.com/strata/strata/agent/gen/strata/event/v1"
)

func TestCanarySourceOverflowDoesNotForceShadow(t *testing.T) {
	s := newSim(t, 2, CanaryOptions{MaxSources: 2, SourceCap: 100})
	for _, node := range s.nodes {
		s.m.Observe(node, "edge", s.counts[node], s.now)
	}
	st := s.m.group("edge")
	st.learnt, st.ref = 12, 0.001
	st.deltas = append(st.deltas, canaryDelta{at: s.now, c: groupCounts{req: 1000, blocked: 202}, s: groupCounts{req: 1000}})
	for i, ip := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"} {
		for j := 0; j < []int{1, 1, 200}[i]; j++ {
			s.m.ObserveEvent(s.nodes[j%2], &eventv1.Event{BlockId: "STR-test", Action: eventv1.Action_ACTION_BLOCK,
				ClientIp: ip, Canary: eventv1.CanaryGroup_CANARY_GROUP_ENFORCE}, s.now)
		}
	}
	if err := s.m.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(s.st.commands()) != 0 || len(s.st.trips) != 0 {
		t.Fatal("overflow caused a cluster ForceShadow")
	}
	if st.ref != 0.001 || st.learnt != 12 {
		t.Fatalf("overflow changed the baseline: %v/%d", st.ref, st.learnt)
	}
	if sb, sw, saturated := s.m.bySource(st); sb != 2 || sw != 2 || !saturated || s.m.SourceSaturations() != 1 {
		t.Fatalf("unbounded counts or wrong saturation metric: %d/%d/%v", sb, sw, saturated)
	}
	// Another complete bucket must not clear an overflow still in the window.
	s.now = s.now.Add(2 * s.m.o.Interval)
	s.events(s.nodes[0], 100, 0, 1)
	st.deltas = append(st.deltas, canaryDelta{at: s.now, c: groupCounts{req: 1000, blocked: 100}, s: groupCounts{req: 1000}})
	if err := s.m.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(s.st.trips) != 0 || st.ref != 0.001 || st.learnt != 12 {
		t.Fatal("the incomplete window was used for a decision or learning")
	}
	// Once all unreliable buckets expire, a real block surge can trip again.
	s.now = s.now.Add(s.m.o.Window + time.Second)
	s.events(s.nodes[0], 100, 0, 1)
	st.deltas = append(st.deltas, canaryDelta{at: s.now, c: groupCounts{req: 1000, blocked: 100}, s: groupCounts{req: 1000}})
	if err := s.m.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(s.st.trips) != 1 || s.st.trips[0].Reason != TripBlockRate {
		t.Fatal("block-rate fallback did not recover after the window expired")
	}
}

func TestCanarySaturationKeepsIndependentSignals(t *testing.T) {
	m := NewCanaryMonitor(nil, nil, CanaryOptions{})
	st := &groupState{learnt: 12, ref: 0.001}
	for _, tc := range []struct {
		x5      uint64
		latency [9]uint64
		want    string
	}{
		{x5: 200, want: Trip5xx},
		{latency: [9]uint64{6: 1000}, want: TripLatency},
	} {
		v := m.judge(st, groupCounts{req: 1000, x5: tc.x5, lat: tc.latency},
			groupCounts{req: 1000, lat: [9]uint64{1000}}, 1000, 1000, true)
		if v.reason != tc.want || v.enough {
			t.Fatalf("independent signal %s lost or incomplete baseline learnt: %+v", tc.want, v)
		}
	}
}
