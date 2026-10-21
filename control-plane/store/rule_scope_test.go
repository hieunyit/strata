package store_test

import (
	"errors"
	"testing"
	"time"

	"github.com/strata/strata/control-plane/auth"
	"github.com/strata/strata/control-plane/localauth/localauthtest"
	"github.com/strata/strata/control-plane/store"
)

func TestRuleFPRespectsRouteScope(t *testing.T) {
	pool := localauthtest.Pool(t)
	s := store.New(pool)
	ctx := t.Context()
	now := time.Now().UTC().Truncate(time.Millisecond)
	a := store.Audit{Actor: "operator", Subject: "oidc:operator", Action: "events.markFalsePositive", RuleContext: &store.EventRuleContext{BundleVersion: 1, PolicyID: "example-api", EventTime: now, RuleIDs: []uint32{942100}, NodeID: "node-a", HTTPHost: "api.example.test", HTTPPath: "/allowed/search"}}
	// A case created first must not suppress the first actual FP automation report.
	c, err := s.SaveEventCase(ctx, store.EventCase{BlockID: "block-a", Status: "open"}, store.Audit{Actor: "operator", Subject: "oidc:operator", Action: "case.create", RequestID: "case"})
	if err != nil {
		t.Fatal(err)
	}
	rows, err := s.EventAnnotations(ctx, []string{c.BlockID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.MarkEventFalsePositive(ctx, c.BlockID, "legitimate", rows[c.BlockID].Etag, a); err != nil {
		t.Fatal(err)
	}
	var reported *time.Time
	if err := pool.QueryRow(ctx, `SELECT first_reported_at FROM rule_annotation_context WHERE block_id=$1`, c.BlockID).Scan(&reported); err != nil || reported == nil {
		t.Fatalf("case hid first report: %v %v", reported, err)
	}
	a.RuleContext.HTTPPath = "/private/search"
	if _, err := s.MarkEventFalsePositive(ctx, "block-b", "private", "", a); err != nil {
		t.Fatal(err)
	}
	scoped := auth.WithPrincipal(ctx, &auth.Principal{Access: &auth.Access{Events: []auth.EventScope{{Policy: "example-api", Host: "api.example.test", Prefix: "/allowed", Nodes: []string{"node-a"}}}}})
	got, err := s.RuleFalsePositiveEvents(scoped, 942100, "", now.Add(-time.Second), now.Add(time.Second))
	if err != nil || got != 1 {
		t.Fatalf("scoped FP count=%d %v", got, err)
	}
	empty := auth.WithPrincipal(ctx, &auth.Principal{Access: &auth.Access{}})
	got, err = s.RuleFalsePositiveEvents(empty, 942100, "", now.Add(-time.Second), now.Add(time.Second))
	if err != nil || got != 0 {
		t.Fatalf("empty scope=%d %v", got, err)
	}
	a.RuleContext.NodeID = ""
	if _, err := s.MarkEventFalsePositive(ctx, "block-legacy", "old", "", a); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RuleFalsePositiveEvents(scoped, 942100, "", now.Add(-time.Second), now.Add(time.Second)); !errors.Is(err, store.ErrRuleContextScopeIncomplete) {
		t.Fatalf("legacy must be unknown: %v", err)
	}
}
