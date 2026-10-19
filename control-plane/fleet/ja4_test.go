package fleet

import (
	"context"
	"testing"
	"time"

	eventv1 "github.com/strata/strata/agent/gen/strata/event/v1"
	fleetv1 "github.com/strata/strata/agent/gen/strata/fleet/v1"
	"github.com/strata/strata/control-plane/ingest"
)

// RV-N-02: the JA4 of an event reaches the store; a malformed one is
// dropped by validation, never stored.
func TestPushEventsKeepsTheJA4(t *testing.T) {
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
	good := event("STR-8F3K-Q2VD-7XNM-A1PC")
	good.Ja4 = "t13d1516h2_8daaf6152771_02713d6af862"
	bad := event("STR-8F3K-Q2VD-7XNM-A1PD")
	bad.Ja4 = "t13d1516h2_8daaf6152771_<script>xx"
	b := &fleetv1.EventBatch{Seq: 1, Events: []*eventv1.Event{good, bad}}
	if _, err := push(t, cl, b, b); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ id, want string }{{good.BlockId, good.Ja4}, {bad.BlockId, ""}} {
		got, err := store.GetEvent(t.Context(), c.id)
		if err != nil {
			t.Fatal(err)
		}
		if got.JA4 != c.want {
			t.Errorf("%s: ja4 %q, want %q", c.id, got.JA4, c.want)
		}
	}
}
