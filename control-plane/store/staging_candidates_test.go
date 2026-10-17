package store_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/strata/strata/control-plane/localauth/localauthtest"
	"github.com/strata/strata/control-plane/store"
)

func TestStagingCandidatesUseImmutableReportsAndAdvanceCursor(t *testing.T) {
	p := localauthtest.Pool(t)
	s := store.New(p)
	ctx := t.Context()
	now := time.Now().UTC().Truncate(time.Microsecond)
	mark := func(block, name string, bundle uint64, rules []uint32) {
		t.Helper()
		_, err := s.MarkEventFalsePositive(ctx, block, "normal", "", store.Audit{Actor: "operator", Subject: "operator", RequestID: "mark-" + block, RuleContext: &store.EventRuleContext{PolicyID: name, EventTime: now, BundleVersion: bundle, RuleIDs: rules}})
		if err != nil {
			t.Fatal(err)
		}
	}
	mark("a-1", "example-a", 7, []uint32{42})
	mark("a-2", "example-a", 7, []uint32{42})
	mark("b-1", "example-b", 7, []uint32{43})
	mark("ambiguous", "example-a", 7, []uint32{42, 43})
	mark("wrong-bundle", "example-a", 8, []uint32{42})
	mark("wrong-policy", "other", 7, []uint32{42})
	if _, err := s.MarkEventFalsePositive(ctx, "legacy", "normal", "", store.Audit{Actor: "operator", Subject: "operator"}); err != nil {
		t.Fatal(err)
	}
	// Retrying the same report cannot create more eligible evidence.
	mark("a-1", "example-a", 7, []uint32{42})
	scopes := []store.StagingScope{{PolicyName: "example-a", RuleID: 42, From: now.Add(-time.Hour), To: now.Add(time.Minute), MinReports: 2}, {PolicyName: "example-b", RuleID: 43, From: now.Add(-time.Hour), To: now.Add(time.Minute), MinReports: 1}}
	page, err := s.StagingCandidates(ctx, 7, scopes, "", 0, 1)
	if err != nil || len(page) != 1 || page[0].PolicyName != "example-a" || page[0].Reports != 2 {
		t.Fatalf("first: %v %v", page, err)
	}
	next, err := s.StagingCandidates(ctx, 7, scopes, page[0].PolicyName, page[0].RuleID, 1)
	if err != nil || len(next) != 1 || next[0].PolicyName != "example-b" || next[0].Reports != 1 {
		t.Fatalf("next: %v %v", next, err)
	}
	end, err := s.StagingCandidates(ctx, 7, scopes, next[0].PolicyName, next[0].RuleID, 1)
	if err != nil || len(end) != 0 {
		t.Fatalf("end: %v %v", end, err)
	}
	scopes[0].MinReports = 3
	page, err = s.StagingCandidates(ctx, 7, scopes, "", 0, 64)
	if err != nil || len(page) != 1 || page[0].PolicyName != "example-b" {
		t.Fatalf("minimum: %v %v", page, err)
	}
	scopes[0].MinReports = 2
	scopes[0].To = now // event cohort upper bound is exclusive
	page, err = s.StagingCandidates(ctx, 7, scopes, "", 0, 64)
	if err != nil || len(page) != 1 || page[0].PolicyName != "example-b" {
		t.Fatalf("half-open: %v %v", page, err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err = s.StagingCandidates(canceled, 7, scopes, "", 0, 1); err == nil {
		t.Fatal("canceled query ran")
	}
}

func TestStagingCandidateBounds(t *testing.T) {
	s := store.New(localauthtest.Pool(t))
	now := time.Now().UTC()
	base := store.StagingScope{PolicyName: "example-api", RuleID: 42, From: now.Add(-time.Hour), To: now, MinReports: 1}
	for _, bad := range []store.StagingScope{{}, {PolicyName: "example-api", RuleID: 42, From: now.Add(-25 * time.Hour), To: now, MinReports: 1}, {PolicyName: "example-api", RuleID: 42, From: now.Add(-time.Hour), To: now}} {
		if _, err := s.StagingCandidates(t.Context(), 7, []store.StagingScope{bad}, "", 0, 1); err == nil {
			t.Fatal("invalid scope accepted")
		}
	}
	if _, err := s.StagingCandidates(t.Context(), 7, []store.StagingScope{base, base}, "", 0, 1); err == nil {
		t.Fatal("duplicate scope")
	}
	if _, err := s.StagingCandidates(t.Context(), 7, []store.StagingScope{base}, "", 0, 65); err == nil {
		t.Fatal("unbounded page")
	}
	scopes := []store.StagingScope{}
	for i := 0; i < 17; i++ {
		q := base
		q.RuleID = uint32(i + 1)
		scopes = append(scopes, q)
	}
	if _, err := s.StagingCandidates(t.Context(), 7, scopes, "", 0, 1); err == nil {
		t.Fatal("too many per-policy scopes")
	}
	scopes = nil
	for i := 0; i < 4097; i++ {
		q := base
		q.PolicyName = fmt.Sprintf("example-%d", i)
		scopes = append(scopes, q)
	}
	if _, err := s.StagingCandidates(t.Context(), 7, scopes, "", 0, 1); err == nil {
		t.Fatal("too many policies")
	}

	// Global raw input cap is checked before JSON/database I/O.
	if _, err := s.StagingCandidates(t.Context(), 7, make([]store.StagingScope, 65537), "", 0, 1); err == nil {
		t.Fatal("too many scopes")
	}
}
