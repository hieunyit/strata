package store_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/strata/strata/control-plane/localauth/localauthtest"
	"github.com/strata/strata/control-plane/store"
)

func TestInvestigationPersistence(t *testing.T) {
	pool := localauthtest.Pool(t)
	ctx := t.Context()
	s := store.New(pool)
	for _, q := range []string{`INSERT INTO connector_groups(id,name) VALUES('example-group','Example')`, `INSERT INTO applications(id,name,owner,etag,created_by) VALUES('example-api','Example','operator','e','operator')`, `INSERT INTO application_environments(application_id,id,name,group_id) VALUES('example-api','test','Test','example-group')`} {
		if _, err := pool.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	a := store.Audit{Subject: "local:operator", Actor: "operator", Action: "search.save", RequestID: "save-a"}
	input := store.SavedSearch{ApplicationID: "example-api", EnvironmentID: "test", Title: "Investigation", Filter: json.RawMessage(`{"action":"block"}`)}
	first, err := s.SaveSearch(ctx, input, true, a)
	if err != nil {
		t.Fatal(err)
	}
	again, err := store.New(pool).SaveSearch(ctx, input, true, a)
	if err != nil || first.ID != again.ID || first.Etag != again.Etag {
		t.Fatalf("retry: %+v %v", again, err)
	}
	input.Shared = true
	if _, err := s.SaveSearch(ctx, input, true, a); !errors.Is(err, store.ErrRequestReused) {
		t.Fatalf("changed retry: %v", err)
	}
	changed := first
	changed.Title = "Updated"
	a.RequestID = "save-b"
	changed, err = s.SaveSearch(ctx, changed, false, a)
	if err != nil {
		t.Fatal(err)
	}
	a.RequestID = "save-c"
	if _, err := s.SaveSearch(ctx, first, false, a); !errors.Is(err, store.ErrEtagMismatch) {
		t.Fatalf("stale etag: %v", err)
	}
	rows, err := s.SavedSearches(ctx, "example-api", "test", "someone-else", "")
	if err != nil || len(rows) != 0 {
		t.Fatalf("private list: %v %v", rows, err)
	}
	a.Action = "event.case"
	a.RequestID = "case-a"
	v, err := s.SaveEventCase(ctx, store.EventCase{BlockID: "block-a", Assignee: a.Subject, Status: "investigating", Note: "Review sample"}, a)
	if err != nil {
		t.Fatal(err)
	}
	annotations, err := s.EventAnnotations(ctx, []string{"block-a"})
	if err != nil || !annotations["block-a"].CaseOnly {
		t.Fatalf("case marked FP: %+v %v", annotations, err)
	}
	fetched, err := store.New(pool).EventCase(ctx, "block-a")
	if err != nil || fetched.Etag != v.Etag || fetched.Note != v.Note {
		t.Fatalf("case restart: %+v %v", fetched, err)
	}
	a.Action = "events.markFalsePositive"
	a.RequestID = "fp"
	if _, err := s.MarkEventFalsePositive(ctx, "block-a", "legitimate", annotations["block-a"].Etag, a); err != nil {
		t.Fatal(err)
	}
	annotations, err = s.EventAnnotations(ctx, []string{"block-a"})
	if err != nil || annotations["block-a"].CaseOnly {
		t.Fatalf("FP not marked: %+v %v", annotations, err)
	}
	a.Action = "event.case"
	a.RequestID = "case-b"
	v.Note = "Resolved"
	v.Status = "resolved"
	if _, err := s.SaveEventCase(ctx, v, a); err != nil {
		t.Fatal(err)
	}
	annotations, err = s.EventAnnotations(ctx, []string{"block-a"})
	if err != nil || annotations["block-a"].CaseOnly {
		t.Fatal("case edit lost FP")
	}
	// Expiry removes note/filter and replayable note copies. Local audit has no PII.
	if _, err := pool.Exec(ctx, `UPDATE event_annotations SET case_expires_at=now()-interval '1 second'; UPDATE saved_searches SET expires_at=now()-interval '1 second'; UPDATE investigation_requests SET created_at=now()-interval '31 days'`); err != nil {
		t.Fatal(err)
	}
	if err := s.PurgeInvestigationContent(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SavedSearch(ctx, first.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expired search: %v", err)
	}
	if _, err := s.EventCase(ctx, "block-a"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expired case: %v", err)
	}
	entries, err := s.AuditEntries(ctx, 20)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Action == "event.case" || entry.Action == "search.save" {
			if entry.After != nil || entry.Before != nil {
				t.Fatal("audit copied private content")
			}
		}
	}
	_ = changed
}
