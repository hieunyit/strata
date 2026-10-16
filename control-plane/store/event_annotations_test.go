package store_test

import (
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/strata/strata/control-plane/localauth/localauthtest"
	"github.com/strata/strata/control-plane/store"
)

func TestEventAnnotationsInPostgres(t *testing.T) {
	p := localauthtest.Pool(t)
	ctx := t.Context()
	s := store.New(p)
	audit := store.Audit{Actor: "operator", Subject: "operator-sub", Action: "events.markFalsePositive", Resource: "events/block-a", RequestID: "request-a"}
	first, err := s.MarkEventFalsePositive(ctx, "block-a", "legitimate login", "", audit)
	if err != nil {
		t.Fatal(err)
	}
	if first.Etag == "" || first.MarkedAt.IsZero() || first.MarkedSubject != audit.Subject {
		t.Fatalf("incomplete annotation: %+v", first)
	}
	retry, err := store.New(p).MarkEventFalsePositive(ctx, "block-a", "legitimate login", "", audit)
	if err != nil || retry != first {
		t.Fatalf("retry: %+v %v", retry, err)
	}
	if _, err := s.MarkEventFalsePositive(ctx, "block-b", "legitimate login", "", audit); !errors.Is(err, store.ErrRequestReused) {
		t.Fatalf("request reuse: %v", err)
	}
	audit.RequestID = "request-b"
	if _, err := s.MarkEventFalsePositive(ctx, "block-a", "updated reason", "", audit); !errors.Is(err, store.ErrEtagMismatch) {
		t.Fatalf("missing etag: %v", err)
	}
	updated, err := s.MarkEventFalsePositive(ctx, "block-a", "updated reason", first.Etag, audit)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Etag == first.Etag {
		t.Fatal("etag did not change")
	}
	audit.RequestID = "request-a"
	retry, err = s.MarkEventFalsePositive(ctx, "block-a", "legitimate login", "", audit)
	if err != nil || retry != first {
		t.Fatalf("delayed retry after edit: %+v %v", retry, err)
	}
	rows, err := store.New(p).EventAnnotations(ctx, []string{"block-a", "missing"})
	if err != nil || len(rows) != 1 || rows["block-a"] != updated {
		t.Fatalf("restart read: %+v %v", rows, err)
	}
	entries, err := s.AuditEntries(ctx, 10)
	if err != nil || len(entries) != 2 {
		t.Fatalf("audit entries=%d err=%v", len(entries), err)
	}
	if entries[0].Before == nil || entries[0].After == nil {
		t.Fatal("missing audit diff")
	}
	// A failed audit rolls back both the annotation and the request record.
	audit.Channel = "invalid"
	audit.RequestID = "rollback"
	if _, err := s.MarkEventFalsePositive(ctx, "rollback", "normal", "", audit); err == nil {
		t.Fatal("invalid audit succeeded")
	}
	rows, err = s.EventAnnotations(ctx, []string{"rollback"})
	if err != nil || len(rows) != 0 {
		t.Fatalf("audit failure leaked write: %+v %v", rows, err)
	}
	audit.Channel = "api"
	audit.RequestID = ""
	var successes atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := store.New(p).MarkEventFalsePositive(ctx, "race", "normal", "", audit)
			if err == nil {
				successes.Add(1)
			} else if !errors.Is(err, store.ErrEtagMismatch) {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatalf("concurrent initial writes=%d", successes.Load())
	}
	for _, reason := range []string{"", " ", strings.Repeat("x", 501)} {
		if _, err := s.MarkEventFalsePositive(ctx, "invalid", reason, "", audit); err == nil {
			t.Fatal("invalid reason accepted")
		}
	}
	if _, err := s.EventAnnotations(ctx, make([]string, 201)); err == nil {
		t.Fatal("oversized page accepted")
	}
}
