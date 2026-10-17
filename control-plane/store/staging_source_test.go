package store_test

import (
	"errors"
	"testing"

	"github.com/strata/strata/control-plane/store"
)

func TestStagingSourceNeedsActualACKAndKeepsHistoricalVersions(t *testing.T) {
	p, s, source, b, a := stagingFixture(t)
	ctx := t.Context()
	audit := store.Audit{Actor: "worker", Channel: "system"}
	check := func(version uint64, want bool) {
		t.Helper()
		ready, err := s.StagingSourceReady(ctx, version)
		if err != nil || ready != want {
			t.Fatalf("source %d ready=%v want=%v err=%v", version, ready, want, err)
		}
	}
	check(0, false)
	check(1, false)
	if _, _, err := s.CreateRollout(ctx, 1, nil, []float64{1}, 0, audit); err != nil {
		t.Fatal(err)
	}
	check(1, false) // DONE without nodes is not activation evidence.
	if _, err := p.Exec(ctx, `INSERT INTO connector_groups(id,name) VALUES('example-edge','example-edge'); INSERT INTO nodes(id,group_id) VALUES('example-node','example-edge')`); err != nil {
		t.Fatal(err)
	}
	ro, _, err := s.CreateRollout(ctx, 1, []string{"example-node"}, []float64{1}, 0, audit)
	if err != nil {
		t.Fatal(err)
	}
	check(1, false)
	if err = s.ReportBundleStatus(ctx, "example-node", 1, "ACTIVE", ""); err != nil {
		t.Fatal(err)
	}
	check(1, false) // Still RUNNING until its rollout completes.
	if _, err = s.AdvanceRollout(ctx, ro.ID); err != nil {
		t.Fatal(err)
	}
	check(1, true)
	if _, err = p.Exec(ctx, `UPDATE nodes SET bundle_state='VERIFIED' WHERE id='example-node'`); err != nil {
		t.Fatal(err)
	}
	check(1, false)
	if err = s.ReportBundleStatus(ctx, "example-node", 1, "ACTIVE", ""); err != nil {
		t.Fatal(err)
	}
	current, err := s.GetPolicy(ctx, "example-api")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.UpdatePolicy(ctx, current.ID, current.Etag, []byte(`{"mode":"shadow"}`), store.Audit{Actor: "operator", Subject: "operator"}); err != nil {
		t.Fatal(err)
	}
	policies, err := s.BundlePolicies(ctx, 1)
	if err != nil || len(policies) != 1 || policies[0].CurrentVersion != 1 || string(policies[0].Spec) == `{"mode":"shadow"}` {
		t.Fatalf("source replaced by newest draft: %+v %v", policies, err)
	}
	if _, err = s.RecordStagingBundle(ctx, source, b, a, audit); err != nil {
		t.Fatal(err)
	}
	root, err := s.StagingRoot(ctx, 2)
	if err != nil || root.Version != 1 || root.InputDigest != source.InputDigest {
		t.Fatalf("wrong root: %+v %v", root, err)
	}
	check(1, false)
	check(2, false)
	if _, err = s.GetBundle(ctx, 999); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown source: %v", err)
	}
	if _, err = s.BundlePolicies(ctx, 999); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown policy set: %v", err)
	}
	b.Version = 3
	b.ObjectKey = "bundles/3"
	if _, err = s.RecordBundle(ctx, b, audit); err != nil {
		t.Fatal(err)
	}
	root, err = s.StagingRoot(ctx, 3)
	if err != nil || root.Version != 3 {
		t.Fatalf("ordinary bundle inherited old root: %+v %v", root, err)
	}
}
