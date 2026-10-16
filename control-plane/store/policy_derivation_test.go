package store_test

import (
	"encoding/json"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/strata/strata/control-plane/localauth/localauthtest"
	"github.com/strata/strata/control-plane/store"
)

func TestDerivedPolicyDraftRunsOnceInPostgres(t *testing.T) {
	pool := localauthtest.Pool(t)
	ctx := t.Context()
	s := store.New(pool)
	audit := store.Audit{Actor: "operator", Subject: "operator-sub", Channel: "api", Action: "policy.create", Resource: "policies/example-api"}
	first, err := s.CreatePolicy(ctx, store.Policy{ID: "example-api", Name: "example-api", Spec: []byte(`{"mode":"shadow"}`)}, audit)
	if err != nil {
		t.Fatal(err)
	}
	audit.Action = "exceptions.fromBlockId"
	audit.RequestID = "generated"
	command := json.RawMessage(`{"reason":"legitimate login","ttl_seconds":3600}`)
	var calls atomic.Int64
	derive := func(before store.Policy) (json.RawMessage, error) {
		if before.Etag != first.Etag || before.CurrentVersion != 1 {
			t.Error("callback did not see locked original policy")
		}
		n := calls.Add(1)
		return json.Marshal(map[string]any{"mode": "shadow", "generated": n})
	}
	var wg sync.WaitGroup
	replies := make(chan store.Policy, 12)
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p, err := store.New(pool).EditPolicyOnce(ctx, first.ID, first.Etag, command, audit, derive)
			if err != nil {
				t.Error(err)
				return
			}
			replies <- p
		}()
	}
	wg.Wait()
	close(replies)
	var edited store.Policy
	count := 0
	for p := range replies {
		if count == 0 {
			edited = p
		}
		if !reflect.DeepEqual(edited, p) {
			t.Error("retry replies differ")
		}
		count++
	}
	if count != 12 || calls.Load() != 1 {
		t.Fatalf("replies=%d derivations=%d", count, calls.Load())
	}
	laterAudit := audit
	laterAudit.RequestID = "later"
	later, err := s.UpdatePolicy(ctx, first.ID, edited.Etag, json.RawMessage(`{"mode":"enforce"}`), laterAudit)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := store.New(pool).EditPolicyOnce(ctx, first.ID, first.Etag, command, audit, derive)
	if err != nil || !reflect.DeepEqual(retry, edited) || calls.Load() != 1 {
		t.Fatal("delayed retry regenerated the draft", err)
	}
	if _, err := s.EditPolicyOnce(ctx, first.ID, first.Etag, json.RawMessage(`{"reason":"changed"}`), audit, derive); !errors.Is(err, store.ErrRequestReused) {
		t.Fatalf("different command accepted: %v", err)
	}
	other := audit
	other.Subject = "another-subject"
	if _, err := s.EditPolicyOnce(ctx, first.ID, first.Etag, command, other, derive); !errors.Is(err, store.ErrEtagMismatch) {
		t.Fatalf("another actor obtained cached response: %v", err)
	}
	failed := audit
	failed.RequestID = "derive-error"
	if _, err := s.EditPolicyOnce(ctx, first.ID, later.Etag, command, failed, func(store.Policy) (json.RawMessage, error) { return nil, errors.New("cannot derive") }); err == nil {
		t.Fatal("failed callback committed")
	}
	current, err := s.GetPolicy(ctx, first.ID)
	if err != nil || current.Etag != later.Etag {
		t.Fatal("failed callback changed policy")
	}
	if _, err := s.EditPolicyOnce(ctx, first.ID, later.Etag, command, failed, func(p store.Policy) (json.RawMessage, error) { return p.Spec, nil }); err != nil {
		t.Fatal("failed callback consumed request_id", err)
	}
}
