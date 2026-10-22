package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/strata/strata/control-plane/rulesets"
	"github.com/strata/strata/control-plane/store"
)

// RS-3c: custom rule sets, versioned by etag, audited.
func TestCustomRuleSetsInPostgres(t *testing.T) {
	pool := migratedPool(t)
	s := store.New(pool)
	ctx := context.Background()
	a := store.Audit{Actor: "example-operator", Subject: "oidc:op", Action: "POST /v1/rule-sets"}
	set := store.CustomRuleSet{Name: "custom-internal-scanners", Title: "Internal scanners", Match: rulesets.Filter{Tags: []string{"scanner"}, IDs: []uint32{913100}}}
	created, err := s.CreateCustomRuleSet(ctx, set, a)
	if err != nil || created.Version != 1 || created.Etag == "" || created.CreatedBy != "example-operator" {
		t.Fatalf("create %+v %v", created, err)
	}
	if _, err := s.CreateCustomRuleSet(ctx, set, a); !errors.Is(err, store.ErrCustomRuleSetConflict) {
		t.Fatalf("name taken: %v", err)
	}
	for _, bad := range []store.CustomRuleSet{
		{Name: "bots-scanners", Title: "x", Match: rulesets.Filter{Tags: []string{"x"}}},
		{Name: "custom-x", Title: " ", Match: rulesets.Filter{Tags: []string{"x"}}},
		{Name: "custom-x", Title: "x"},
		{Name: "custom-x", Title: "x", Match: rulesets.Filter{IDs: []uint32{1, 1}}},
	} {
		if _, err := s.CreateCustomRuleSet(ctx, bad, a); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	set.Title, set.Match = "Internal scanners and probes", rulesets.Filter{AttackTypes: []string{"scanner"}}
	if _, err := s.UpdateCustomRuleSet(ctx, set, "stale", a); !errors.Is(err, store.ErrCustomRuleSetConflict) {
		t.Fatalf("stale etag: %v", err)
	}
	updated, err := s.UpdateCustomRuleSet(ctx, set, created.Etag, a)
	if err != nil || updated.Version != 2 || updated.Etag == created.Etag || updated.Match.AttackTypes[0] != "scanner" || updated.Match.IDs != nil {
		t.Fatalf("update %+v %v", updated, err)
	}
	list, err := s.ListCustomRuleSets(ctx)
	if err != nil || len(list) != 1 || list[0].Title != "Internal scanners and probes" {
		t.Fatalf("list %+v %v", list, err)
	}
	if err := s.DeleteCustomRuleSet(ctx, set.Name, created.Etag, a); !errors.Is(err, store.ErrCustomRuleSetConflict) {
		t.Fatalf("delete with a stale etag: %v", err)
	}
	if err := s.DeleteCustomRuleSet(ctx, set.Name, updated.Etag, a); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetCustomRuleSet(ctx, set.Name); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("after delete: %v", err)
	}
	var n int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM audit_log WHERE resource = 'rule-sets/custom-internal-scanners'").Scan(&n); err != nil || n != 3 {
		t.Fatalf("audit rows %d %v", n, err)
	}
}
