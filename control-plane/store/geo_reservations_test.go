package store_test

import (
	"encoding/json"
	"fmt"
	"sync"
	"testing"

	"github.com/strata/strata/control-plane/localauth/localauthtest"
	"github.com/strata/strata/control-plane/store"
)

func TestGeoDraftIDsConcurrent(t *testing.T) {
	pool := localauthtest.Pool(t)
	s := store.New(pool)
	ctx := t.Context()
	var policies []store.Policy
	for i := range 8 {
		id := fmt.Sprintf("policy-%d", i)
		p, err := s.CreatePolicy(ctx, store.Policy{ID: id, Name: id, Spec: []byte(`{"mode":"shadow"}`)}, store.Audit{Actor: "operator", Subject: "oidc:operator", Action: "policy.create"})
		if err != nil {
			t.Fatal(err)
		}
		policies = append(policies, p)
	}
	var wg sync.WaitGroup
	for _, p := range policies {
		wg.Go(func() {
			a := store.Audit{Actor: "operator", Subject: "oidc:operator", Action: "geo.propose", RequestID: p.ID}
			_, err := s.EditGeoPolicyAndReplayOnce(ctx, p.ID, p.Etag, []byte(`{"dimension":"country"}`), a, func(before store.Policy, id uint32) (json.RawMessage, error) {
				return json.RawMessage(fmt.Sprintf(`{"mode":"shadow","geo_rules":[{"id":%d,"countries":["VN"],"action":"log"}]}`, id)), nil
			})
			if err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(DISTINCT rule_id) FROM policy_geo_rule_ids`).Scan(&count); err != nil || count != 8 {
		t.Fatalf("IDs %d %v", count, err)
	}
	var collision int
	if err := pool.QueryRow(ctx, `SELECT rule_id FROM policy_geo_rule_ids WHERE policy_id=$1`, policies[0].ID).Scan(&collision); err != nil {
		t.Fatal(err)
	}
	_, err := s.UpdatePolicy(ctx, policies[1].ID, "invalid-etag", nil, store.Audit{})
	if err == nil {
		t.Fatal("missing etag accepted")
	}
	// The guard applies to all policy writers, not only the new proposal API.
	_, err = pool.Exec(ctx, `INSERT INTO policy_versions(policy_id,version,spec,created_by) VALUES($1,9,$2,'operator')`, policies[1].ID, fmt.Sprintf(`{"mode":"shadow","geo_rules":[{"id":%d}]}`, collision))
	if err == nil {
		t.Fatal("cross-policy ID collision committed")
	}
}
