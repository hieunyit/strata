package store_test

import (
	"errors"
	"sync"
	"testing"

	"github.com/strata/strata/control-plane/fleet"
	"github.com/strata/strata/control-plane/store"
)

func TestStagingRolloutSurvivesRestartWithoutDuplicates(t *testing.T) {
	p, s, source, b, a := stagingFixture(t)
	ctx := t.Context()
	audit := store.Audit{Actor: "worker", Channel: "system"}
	if _, err := p.Exec(ctx, `INSERT INTO connector_groups(id,name) VALUES('example-edge','example-edge'); INSERT INTO nodes(id,group_id) VALUES('example-node','example-edge')`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RecordStagingBundle(ctx, source, b, a, audit); err != nil {
		t.Fatal(err)
	}
	pending, err := store.New(p).LatestStagingAction(ctx)
	if err != nil || pending.RolloutID != nil || pending.ID != a.ID {
		t.Fatalf("lost record-before-publish intent: %+v %v", pending, err)
	}
	if _, _, err := s.StartStagingRollout(ctx, a.ID, []string{"example-node"}, []float64{1}, 0, store.Audit{Channel: "invalid"}); err == nil {
		t.Fatal("bad audit accepted")
	}
	pending, err = s.LatestStagingAction(ctx)
	if err != nil || pending.RolloutID != nil {
		t.Fatalf("failed audit linked rollout: %+v %v", pending, err)
	}
	// Two replicas recovering the same committed action create one rollout.
	var wg sync.WaitGroup
	ids := make(chan int64, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, notify, err := store.New(p).StartStagingRollout(ctx, a.ID, []string{"example-node"}, []float64{1}, 0, audit)
			if err != nil {
				t.Error(err)
				return
			}
			if len(notify) != 1 || r.State != store.RolloutRunning {
				t.Errorf("premature active or lost notice: %+v %v", r, notify)
			}
			ids <- r.ID
		}()
	}
	wg.Wait()
	close(ids)
	var id int64
	for current := range ids {
		if id != 0 && current != id {
			t.Fatal("duplicate rollout")
		}
		id = current
	}
	if id == 0 {
		t.Fatal("no rollout")
	}
	var count int
	if err = p.QueryRow(ctx, `SELECT count(*) FROM rollouts`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("rollouts: %d %v", count, err)
	}
	// Crash after rollout commit/before notification: another Store can resend
	// the notice, while desired state remains durable for agent Hello recovery.
	recovered, notify, err := store.New(p).StartStagingRollout(ctx, a.ID, []string{"example-node"}, []float64{1}, 0, audit)
	if err != nil || recovered.ID != id || len(notify) != 1 {
		t.Fatalf("recovery: %+v %v %v", recovered, notify, err)
	}
	// Recovery reaches the actual Fleet presence channel, not a mock callback.
	presence := fleet.NewPresence()
	_, messages, detach := presence.AttachControl(ctx, "example-node")
	defer detach()
	controller := fleet.NewRollouts(store.New(p), presence, []float64{1}, 0)
	if ro, err := controller.StartStaging(ctx, recoveredAction(t, s)); err != nil || ro.ID != id {
		t.Fatalf("fleet recovery: %+v %v", ro, err)
	}
	select {
	case message := <-messages:
		if message.GetBundleAvailable().GetVersion() != 2 {
			t.Fatalf("wrong announcement: %v", message)
		}
	default:
		t.Fatal("recovered rollout did not notify Fleet")
	}
	desired, err := s.DesiredBundle(ctx, "example-node")
	if err != nil || desired.Version != 2 {
		t.Fatalf("desired lost: %+v %v", desired, err)
	}
	if err = s.ReportBundleStatus(ctx, "example-node", 2, "ACTIVE", ""); err != nil {
		t.Fatal(err)
	}
	_, notify, err = s.StartStagingRollout(ctx, a.ID, []string{"example-node"}, []float64{1}, 0, audit)
	if err != nil || len(notify) != 0 {
		t.Fatalf("ACK ignored: %v %v", notify, err)
	}
	if _, err = s.SetRolloutState(ctx, id, store.RolloutPaused, "human pause", []string{store.RolloutRunning}, audit); err != nil {
		t.Fatal(err)
	}
	paused, notify, err := s.StartStagingRollout(ctx, a.ID, []string{"example-node"}, []float64{1}, 0, audit)
	if err != nil || paused.State != store.RolloutPaused || len(notify) != 0 {
		t.Fatalf("automation resumed pause: %+v %v %v", paused, notify, err)
	}
	// A newer human bundle wins; stale outbox retries do not supersede it.
	b.Version = 3
	b.ObjectKey = "bundles/3"
	if _, err = s.RecordBundle(ctx, b, audit); err != nil {
		t.Fatal(err)
	}
	if _, err = s.LatestStagingAction(ctx); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("obsolete outbox selected: %v", err)
	}
	if _, _, err = s.StartStagingRollout(ctx, a.ID, []string{"example-node"}, []float64{1}, 0, audit); !errors.Is(err, store.ErrStagingConflict) {
		t.Fatalf("stale action published: %v", err)
	}
}

func TestStagingRolloutDoesNotSupersedeOrClaimEmptyFleet(t *testing.T) {
	p, s, source, b, a := stagingFixture(t)
	ctx := t.Context()
	audit := store.Audit{Actor: "worker", Channel: "system"}
	if _, err := p.Exec(ctx, `INSERT INTO connector_groups(id,name) VALUES('example-edge','example-edge'); INSERT INTO nodes(id,group_id) VALUES('example-node','example-edge')`); err != nil {
		t.Fatal(err)
	}
	original, _, err := s.CreateRollout(ctx, 1, []string{"example-node"}, []float64{1}, 0, audit)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.RecordStagingBundle(ctx, source, b, a, audit); err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.StartStagingRollout(ctx, a.ID, nil, []float64{1}, 0, audit); err == nil {
		t.Fatal("empty fleet claimed rollout")
	}
	if _, _, err = s.StartStagingRollout(ctx, a.ID, []string{"example-node"}, []float64{1}, 0, audit); !errors.Is(err, store.ErrRolloutState) {
		t.Fatalf("in-flight rollout superseded: %v", err)
	}
	untouched, err := s.GetRollout(ctx, original.ID)
	if err != nil || untouched.State != store.RolloutRunning {
		t.Fatalf("changed original: %+v %v", untouched, err)
	}
}

func recoveredAction(t *testing.T, s *store.Store) store.StagingAction {
	t.Helper()
	a, err := s.LatestStagingAction(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return a
}
