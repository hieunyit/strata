package store_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/strata/strata/control-plane/store"
)

// CP-A07: the bundles kept from pruning come from the database: the newest
// ones, what nodes run and should run, and running or paused rollouts.
func TestKeptBundlesInPostgres(t *testing.T) {
	pool := migratedPool(t)
	s := store.New(pool)
	ctx := context.Background()
	if _, _, err := s.KeptBundles(ctx, 0); err == nil {
		t.Fatal("keeping no bundle accepted")
	}
	for v := uint64(1); v <= 12; v++ {
		if _, err := s.RecordBundle(ctx, store.Bundle{Version: v, SHA256: make([]byte, 32), ObjectKey: fmt.Sprintf("bundles/%d", v), SizeBytes: 1,
			Contents: map[string]int{}}, store.Audit{Actor: "deployer"}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO connector_groups (id, name) VALUES ('edge', 'Edge');
		INSERT INTO nodes (id, group_id, bundle_version, desired_bundle_version) VALUES ('node-a', 'edge', 2, 3), ('node-b', 'edge', NULL, NULL);
		INSERT INTO rollouts (bundle_version, state, waves, created_by) VALUES (5, 'PAUSED', '[1]', 't'), (6, 'DONE', '[1]', 't'), (7, 'ABORTED', '[1]', 't')`); err != nil {
		t.Fatal(err)
	}
	keep, newest, err := s.KeptBundles(ctx, 3)
	if err != nil || newest != 12 {
		t.Fatalf("%v %d %v", keep, newest, err)
	}
	for v := uint64(1); v <= 12; v++ {
		want := v == 2 || v == 3 || v == 5 || v >= 10
		if keep[v] != want {
			t.Errorf("bundle %d kept=%v", v, keep[v])
		}
	}
}
