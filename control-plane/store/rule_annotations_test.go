package store_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/strata/strata/control-plane/db"
	"github.com/strata/strata/control-plane/localauth/localauthtest"
	"github.com/strata/strata/control-plane/store"
)

func TestRuleAnnotationsInPostgres(t *testing.T) {
	p := localauthtest.Pool(t)
	s := store.New(p)
	ctx := t.Context()
	if err := db.Migrate(ctx, p, 18); err != nil {
		t.Fatal(err)
	}
	if _, err := s.MarkEventFalsePositive(ctx, "legacy", "normal", "", store.Audit{Actor: "operator", Subject: "example-operator"}); err != nil {
		t.Fatal(err)
	}
	latest, err := db.Latest()
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(ctx, p, latest); err != nil {
		t.Fatal(err)
	}
	if old, err := s.EventAnnotations(ctx, []string{"legacy"}); err != nil || len(old) != 1 {
		t.Fatalf("migration lost existing annotation: %v %v", old, err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	a := store.Audit{Actor: "operator", Subject: "example-operator", RequestID: "first",
		RuleContext: &store.EventRuleContext{PolicyID: "example-api", EventTime: now, RuleIDs: []uint32{942100, 942100, 0, ^uint32(0)}}}
	first, err := s.MarkEventFalsePositive(ctx, "event-one", "normal request", "", a)
	if err != nil {
		t.Fatal(err)
	}
	count := func(rule uint32, policy string, from, to time.Time, want uint64) {
		t.Helper()
		n, err := store.New(p).RuleFalsePositiveEvents(ctx, rule, policy, from, to)
		if err != nil || n != want {
			t.Fatalf("FP count=%d want=%d: %v", n, want, err)
		}
	}
	count(942100, "example-api", now, now.Add(time.Second), 1)
	count(942100, "example-api", now.Add(time.Nanosecond), now.Add(time.Second), 0)
	count(942100, "example-api", now.Add(-time.Second), now.Add(time.Nanosecond), 1)
	count(942100, "", now, now.Add(time.Second), 1)
	count(^uint32(0), "", now, now.Add(time.Second), 1)
	count(942100, "another-policy", now, now.Add(time.Second), 0)
	count(942100, "", now.Add(-time.Second), now, 0) // exclusive end
	a.RuleContext.RuleIDs = []uint32{42}
	if retry, err := s.MarkEventFalsePositive(ctx, "event-one", "normal request", "", a); err != nil || retry != first {
		t.Fatalf("retry: %+v %v", retry, err)
	}
	count(42, "", now, now.Add(time.Second), 0)
	a.RequestID = "edit"
	if _, err := s.MarkEventFalsePositive(ctx, "event-one", "edited reason", first.Etag, a); err != nil {
		t.Fatal(err)
	}
	count(942100, "", now, now.Add(time.Second), 0)
	count(42, "", now, now.Add(time.Second), 1)
	a.Channel, a.RequestID = "invalid", "rollback"
	if _, err := s.MarkEventFalsePositive(ctx, "rollback", "normal", "", a); err == nil {
		t.Fatal("audit failure accepted")
	}
	var rollbackRows int
	if err := p.QueryRow(ctx, "SELECT count(*) FROM rule_annotation_context WHERE block_id='rollback'").Scan(&rollbackRows); err != nil || rollbackRows != 0 {
		t.Fatalf("context escaped rollback: %d %v", rollbackRows, err)
	}
	a.Channel = "api"
	// Retention deletes bounded batches of context only, leaving human
	// annotation, audit and delayed request-id replay records intact.
	for i := range 2 {
		a.RequestID = fmt.Sprintf("old-%d", i)
		a.RuleContext.EventTime = now.Add(-48 * time.Hour)
		if _, err := s.MarkEventFalsePositive(ctx, a.RequestID, "normal", "", a); err != nil {
			t.Fatal(err)
		}
	}
	for _, want := range []int64{1, 1, 0} {
		if n, err := s.PruneRuleAnnotationContext(ctx, now.Add(-24*time.Hour), 1); err != nil || n != want {
			t.Fatalf("retention=%d want=%d: %v", n, want, err)
		}
	}
	if annotations, err := s.EventAnnotations(ctx, []string{"old-0", "old-1"}); err != nil || len(annotations) != 2 {
		t.Fatalf("retention lost annotation: %v %v", annotations, err)
	}
	a.RuleContext.RuleIDs = make([]uint32, 65)
	a.RequestID = "oversized"
	if _, err := s.MarkEventFalsePositive(ctx, "oversized", "normal", "", a); err == nil {
		t.Fatal("unbounded rule context accepted")
	}
	if _, err := s.RuleFalsePositiveEvents(ctx, 0, "", now, now.Add(time.Second)); err == nil {
		t.Fatal("prefilter counted as a matched rule")
	}
	if _, err := s.RuleFalsePositiveEvents(ctx, 42, "", now, now.Add(25*time.Hour)); err == nil {
		t.Fatal("unbounded query window accepted")
	}
	if _, err := s.PruneRuleAnnotationContext(ctx, now, 1001); err == nil {
		t.Fatal("unbounded retention batch accepted")
	}
}
