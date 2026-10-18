package fleet

import (
	"context"
	"reflect"
	"testing"
	"time"

	eventv1 "github.com/strata/strata/agent/gen/strata/event/v1"
	fleetv1 "github.com/strata/strata/agent/gen/strata/fleet/v1"
	"github.com/strata/strata/control-plane/ingest"
)

func TestPushEventsPreservesSampledRuleCosts(t *testing.T) {
	p := newPKI(t)
	store := ingest.NewMockEventStore()
	svc := ingest.NewIngestService(store, ingest.DefaultBatcherConfig(), time.Hour)
	t.Cleanup(func() {
		if err := svc.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	addr := serve(t, p, svc)
	cert := p.nodeCert(t, "example-node")
	cl := dial(t, p, addr, &cert)
	ev := event("STR-8F3K-Q2VD-7XNM-A1PC")
	ev.RuleCosts = []*eventv1.RuleCost{
		{RuleId: 0, Samples: 2, TotalNs: 700, MaxNs: 500},
		{RuleId: 942100, Samples: 1, TotalNs: 100, MaxNs: 100},
	}
	b := &fleetv1.EventBatch{Seq: 1, Events: []*eventv1.Event{ev}}
	if _, err := push(t, cl, b, b); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetEvent(t.Context(), ev.BlockId)
	if err != nil {
		t.Fatal(err)
	}
	want := []ingest.RuleCost{{RuleID: 0, Samples: 2, TotalNS: 700, MaxNS: 500}, {RuleID: 942100, Samples: 1, TotalNS: 100, MaxNS: 100}}
	if !reflect.DeepEqual(got.RuleCosts, want) || got.NodeID != "example-node" {
		t.Fatalf("sampled costs lost or attributed to wrong node: %+v", got)
	}
	if st := svc.Stats(); st.TotalBatchesAccepted != 1 || st.TotalBatchesDropped != 1 {
		t.Fatalf("retry counted twice: %+v", st)
	}
}

func TestRuleCostsBoundBeforeFleetCopiesAgentInput(t *testing.T) {
	for _, count := range []int{ingest.MaxEventRuleCosts, ingest.MaxEventRuleCosts + 1} {
		ev := event("STR-8F3K-Q2VD-7XNM-A1PC")
		for i := range count {
			ev.RuleCosts = append(ev.RuleCosts, &eventv1.RuleCost{RuleId: uint32(i), Samples: 1})
		}
		got := toIngest(ev, "example-node", time.Now())
		want := count
		if count > ingest.MaxEventRuleCosts {
			want = 0
		}
		if len(got.RuleCosts) != want {
			t.Fatalf("input %d: copied %d costs, want %d", count, len(got.RuleCosts), want)
		}
	}
	ev := event("STR-8F3K-Q2VD-7XNM-A1PC")
	ev.RuleCosts = []*eventv1.RuleCost{nil}
	got := toIngest(ev, "example-node", time.Now())
	if err := ingest.ValidateEvent(&got, time.Now()); err != nil || len(got.RuleCosts) != 0 {
		t.Fatalf("nil optional sample lost security event: %+v, %v", got, err)
	}
}
