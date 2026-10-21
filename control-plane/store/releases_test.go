package store_test

import (
	"errors"
	"testing"
	"time"

	"github.com/strata/strata/control-plane/store"
)

func TestReleaseReviewAndAtomicRolloutInPostgres(t *testing.T) {
	pool := migratedPool(t)
	st := store.New(pool)
	ctx := t.Context()
	if _, err := pool.Exec(ctx, `INSERT INTO connector_groups(id,name) VALUES('edge','Edge'); INSERT INTO nodes(id,group_id) VALUES('node-a','edge'); INSERT INTO policies(id,name,etag,created_by) VALUES('example-api','example-api','e','test'); INSERT INTO policy_versions(policy_id,version,spec,created_by) VALUES('example-api',1,'{}','test')`); err != nil {
		t.Fatal(err)
	}
	creator := store.Audit{Subject: "local:operator", Actor: "operator", Action: "release.create"}
	reviewer := store.Audit{Subject: "local:reviewer", Actor: "reviewer", Action: "release.review"}
	b := store.Bundle{Version: 1, SHA256: make([]byte, 32), ObjectKey: "releases/example/snapshot.sbn", SizeBytes: 128, Contents: map[string]int{"example-api": 1}}
	snapshot := store.ReleaseSnapshot{Bundle: b, ReplayIDs: map[string]string{"example-api": "reviewed-operation"}}
	builds := 0
	build := func() (store.ReleaseSnapshot, error) { builds++; return snapshot, nil }
	release, err := st.CreateRelease(ctx, "release-a", "request-a", "", build, creator)
	if err != nil {
		t.Fatal(err)
	}
	again, err := st.CreateRelease(ctx, "release-b", "request-a", "", build, creator)
	if err != nil || again.ID != release.ID || builds != 1 {
		t.Fatalf("retry rebuilt: %d %v", builds, err)
	}
	if _, err := st.LatestBundle(ctx); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("draft changed replay baseline")
	}
	if _, err := st.ReviewRelease(ctx, release.ID, release.Etag, release.SnapshotHash, snapshot.ReplayIDs, true, creator); !errors.Is(err, store.ErrFourEyes) {
		t.Fatalf("self approval: %v", err)
	}
	if _, err := st.ReviewRelease(ctx, release.ID, release.Etag, release.SnapshotHash, map[string]string{}, true, reviewer); !errors.Is(err, store.ErrEtagMismatch) {
		t.Fatal("review did not pin replay IDs")
	}
	release, err = st.ReviewRelease(ctx, release.ID, release.Etag, release.SnapshotHash, snapshot.ReplayIDs, true, reviewer)
	if err != nil {
		t.Fatal(err)
	}
	// A different release/deploy changes the baseline after review.
	baseline := b
	baseline.Version = 2
	baseline.ObjectKey = "bundles/base"
	if _, err := st.RecordBundle(ctx, baseline, creator); err != nil {
		t.Fatal(err)
	}
	target := b
	target.Version = 3
	target.ObjectKey = "bundles/target"
	if _, _, _, err := st.CommitReleaseDeployment(ctx, release.ID, release.Etag, target, nil, []float64{1}, time.Second, creator); !errors.Is(err, store.ErrReleaseBaseline) {
		t.Fatalf("stale baseline silently accepted: %v", err)
	}
	var count int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM bundles WHERE version=3").Scan(&count); err != nil || count != 0 {
		t.Fatal("failed deployment changed bundle state")
	}
	ack := uint64(2)
	// Capability failure rolls back the bundle insert and release transition too.
	target.RequiredCapabilities = []string{"section.16"}
	if _, _, _, err := st.CommitReleaseDeployment(ctx, release.ID, release.Etag, target, &ack, []float64{1}, time.Second, creator); !errors.Is(err, store.ErrIncompatible) {
		t.Fatalf("unknown agent capability accepted: %v", err)
	}
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM bundles WHERE version=3").Scan(&count); err != nil || count != 0 {
		t.Fatal("capability failure partially committed")
	}
	target.RequiredCapabilities = nil
	deployed, ro, first, err := st.CommitReleaseDeployment(ctx, release.ID, release.Etag, target, &ack, []float64{1}, time.Second, creator)
	if err != nil {
		t.Fatal(err)
	}
	if deployed.BundleVersion != 3 || deployed.State != "DEPLOYED" || ro.State != "RUNNING" || len(first) != 1 {
		t.Fatalf("deployment: %+v %+v", deployed, ro)
	}
	if _, _, _, err := st.CommitReleaseDeployment(ctx, release.ID, release.Etag, target, &ack, []float64{1}, time.Second, creator); !errors.Is(err, store.ErrEtagMismatch) {
		t.Fatal("stale etag repeated deployment")
	}
	desired, err := st.DesiredBundle(ctx, "node-a")
	if err != nil || desired.Version != 3 {
		t.Fatalf("desired: %+v %v", desired, err)
	}
}
