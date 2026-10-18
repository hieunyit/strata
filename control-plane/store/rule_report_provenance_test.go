package store_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/strata/strata/control-plane/db"
	"github.com/strata/strata/control-plane/localauth/localauthtest"
	"github.com/strata/strata/control-plane/store"
)

func TestRuleFPReportProvenanceInPostgres(t *testing.T) {
	p := localauthtest.Pool(t)
	ctx := t.Context()
	s := store.New(p)
	if err := db.Migrate(ctx, p, 19); err != nil {
		t.Fatal(err)
	}
	// Seed version-19 data directly; the current writer requires the current schema.
	old := store.EventAnnotation{Etag: "legacy-etag"}
	if _, err := p.Exec(ctx, `INSERT INTO event_annotations(block_id,reason,marked_by,marked_subject,etag) VALUES('legacy','normal','operator','operator','legacy-etag')`); err != nil {
		t.Fatal(err)
	}
	latest, err := db.Latest()
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(ctx, p, latest); err != nil {
		t.Fatal(err)
	}
	// Legacy edits must never become fresh automation evidence.
	now := time.Now().UTC().Truncate(time.Microsecond)
	a := store.Audit{Subject: "operator", Actor: "operator", RuleContext: &store.EventRuleContext{PolicyID: "example-api", EventTime: now, RuleIDs: []uint32{42}}}
	if _, err := s.MarkEventFalsePositive(ctx, "legacy", "updated", old.Etag, a); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := p.QueryRow(ctx, `SELECT count(*) FROM rule_annotation_context WHERE block_id='legacy' AND first_reported_at IS NOT NULL`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("legacy promoted: %d %v", n, err)
	}
	a.RuleContext.BundleVersion = ^uint64(0)
	a.RequestID = "fresh"
	first, err := s.MarkEventFalsePositive(ctx, "fresh", "normal", "", a)
	if err != nil {
		t.Fatal(err)
	}
	count := func(rule uint32, policy string, bundle uint64, ef, et, rf, rt time.Time, want uint64) {
		t.Helper()
		n, err := store.New(p).RuleFPReportCount(ctx, rule, policy, bundle, ef, et, rf, rt)
		if err != nil || n != want {
			t.Fatalf("count=%d want=%d: %v", n, want, err)
		}
	}
	from, to := now.Add(-time.Hour), time.Now().Add(time.Hour)
	count(42, "example-api", ^uint64(0), from, to, from, to, 1)
	count(42, "example-api", 1, from, to, from, to, 0)
	count(42, "another-api", ^uint64(0), from, to, from, to, 0)
	count(43, "example-api", ^uint64(0), from, to, from, to, 0)
	count(42, "example-api", ^uint64(0), now.Add(time.Nanosecond), to, from, to, 0)
	count(42, "example-api", ^uint64(0), from, to, first.MarkedAt.Add(time.Nanosecond), to, 0)
	count(42, "example-api", ^uint64(0), from, to, from, first.MarkedAt, 0)
	count(42, "example-api", ^uint64(0), from, to, from, first.MarkedAt.Add(time.Nanosecond), 1)
	// A changed upstream row/reason cannot move a report to another rule,
	// policy, event cohort or deployed bundle, nor advance first report time.
	a.RuleContext = &store.EventRuleContext{PolicyID: "another-api", BundleVersion: 7, EventTime: now.Add(time.Hour), RuleIDs: []uint32{43}}
	retry, err := s.MarkEventFalsePositive(ctx, "fresh", "normal", "", a)
	if err != nil || retry != first {
		t.Fatalf("retry: %v %v", retry, err)
	}
	a.RequestID = "edit"
	if _, err := s.MarkEventFalsePositive(ctx, "fresh", "edited", first.Etag, a); err != nil {
		t.Fatal(err)
	}
	count(42, "example-api", ^uint64(0), from, to, from, to, 1)
	count(43, "another-api", 7, from, to, from, to, 0)
	var reportAt time.Time
	if err := p.QueryRow(ctx, `SELECT first_reported_at FROM rule_annotation_context WHERE block_id='fresh'`).Scan(&reportAt); err != nil || !reportAt.Equal(first.MarkedAt) {
		t.Fatalf("first time changed: %v %v", reportAt, err)
	}
	// Audit contains the server's bundle snapshot; internal audit context is
	// excluded from Audit JSON, so callers cannot inject it through decoding.
	var audited string
	if err := p.QueryRow(ctx, `SELECT after->'event_context'->>'bundle_version' FROM audit_log WHERE request_id='fresh'`).Scan(&audited); err != nil || audited != "18446744073709551615" {
		t.Fatalf("audit lineage=%s %v", audited, err)
	}
	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	var decoded store.Audit
	if err := json.Unmarshal(raw, &decoded); err != nil || decoded.RuleContext != nil {
		t.Fatalf("internal context serialized: %s %v", raw, err)
	}
	// Reports with ambiguous attribution and unknown bundle cannot trigger.
	for _, tc := range []struct {
		id     string
		ids    []uint32
		bundle uint64
	}{{"multi", []uint32{42, 43}, ^uint64(0)}, {"unknown", []uint32{42}, 0}, {"duplicate", []uint32{42, 42, 0}, 8}} {
		a.RuleContext = &store.EventRuleContext{PolicyID: "example-api", BundleVersion: tc.bundle, EventTime: now, RuleIDs: tc.ids}
		a.RequestID = tc.id
		if _, err := s.MarkEventFalsePositive(ctx, tc.id, "normal", "", a); err != nil {
			t.Fatal(err)
		}
	}
	count(42, "example-api", ^uint64(0), from, to, from, to, 1)
	count(42, "example-api", 8, from, to, from, to, 1)
	a.Channel = "invalid"
	a.RequestID = "rollback"
	if _, err := s.MarkEventFalsePositive(ctx, "rollback", "normal", "", a); err == nil {
		t.Fatal("audit failure accepted")
	}
	if err := p.QueryRow(ctx, `SELECT count(*) FROM rule_annotation_context WHERE block_id='rollback'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("provenance escaped transaction: %d %v", n, err)
	}
	// Retention may remove a snapshot. A reason edit cannot recreate evidence.
	a.Channel = "api"
	a.RequestID = "pruned"
	pruned, err := s.MarkEventFalsePositive(ctx, "pruned", "normal", "", a)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.PruneRuleAnnotationContext(ctx, now.Add(time.Minute), 1000); err != nil {
		t.Fatal(err)
	}
	a.RequestID = "pruned-edit"
	if _, err := s.MarkEventFalsePositive(ctx, "pruned", "edited", pruned.Etag, a); err != nil {
		t.Fatal(err)
	}
	if err := p.QueryRow(ctx, `SELECT count(*) FROM rule_annotation_context WHERE block_id='pruned' AND first_reported_at IS NOT NULL`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("pruned evidence recreated: %d %v", n, err)
	}
	for _, bundle := range []uint64{0, 1} {
		ef, et := from, to
		if bundle != 0 {
			et = ef.Add(25 * time.Hour)
		}
		if _, err := s.RuleFPReportCount(ctx, 42, "example-api", bundle, ef, et, from, to); err == nil {
			t.Fatal("invalid query accepted")
		}
	}
	// Down migration preserves annotations and diagnostic context. Upgrade does
	// not invent provenance for a context retained by that downgrade.
	if err := db.Migrate(ctx, p, 19); err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(ctx, p, latest); err != nil {
		t.Fatal(err)
	}
	if err := p.QueryRow(ctx, `SELECT count(*) FROM rule_annotation_context WHERE first_reported_at IS NOT NULL`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("migration inferred provenance: %d %v", n, err)
	}

}
