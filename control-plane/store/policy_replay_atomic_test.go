package store_test

import (
	"encoding/json"
	"errors"
	"reflect"
	"sync"
	"testing"

	"github.com/strata/strata/control-plane/localauth/localauthtest"
	"github.com/strata/strata/control-plane/store"
)

func TestPolicyDraftAndReplayAtomicInPostgres(t *testing.T) {
	pool := localauthtest.Pool(t)
	ctx := t.Context()
	s := store.New(pool)
	a := store.Audit{Actor: "operator", Subject: "operator-sub", Channel: "api", Action: "policies.create", Resource: "policies/resource-api"}
	first, err := s.CreatePolicy(ctx, store.Policy{ID: "resource-api", Name: "example-api", Spec: []byte(`{"mode":"enforce"}`)}, a)
	if err != nil {
		t.Fatal(err)
	}
	named, err := s.GetPolicyByName(ctx, "example-api")
	if err != nil || named.ID != first.ID {
		t.Fatal("bundle name != resource ID", err)
	}
	if _, err := s.GetPolicyByName(ctx, "missing"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
	a.Action = "exceptions.fromBlockId"
	a.RequestID = "atomic"
	command := json.RawMessage(`{"ttl_seconds":3600}`)
	edit := func(before store.Policy) (json.RawMessage, error) { return before.Spec, nil }
	// Failure after the policy version/audit have been written must roll back all.
	_, err = pool.Exec(ctx, `CREATE FUNCTION fail_replay() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected replay storage failure'; END $$;
 CREATE TRIGGER fail_replay BEFORE INSERT ON operations FOR EACH ROW EXECUTE FUNCTION fail_replay()`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.EditPolicyAndReplayOnce(ctx, first.ID, first.Etag, command, a, edit); err == nil {
		t.Fatal("replay failure committed")
	}
	current, err := s.GetPolicy(ctx, first.ID)
	if err != nil || current.Etag != first.Etag || current.CurrentVersion != 1 {
		t.Fatal("draft leaked", err)
	}
	audits, err := s.AuditEntries(ctx, 100)
	if err != nil || len(audits) != 1 {
		t.Fatal("audit leaked", err)
	}
	if _, err := pool.Exec(ctx, `DROP TRIGGER fail_replay ON operations; DROP FUNCTION fail_replay()`); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	replies := make(chan store.Policy, 12)
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p, err := store.New(pool).EditPolicyAndReplayOnce(ctx, first.ID, first.Etag, command, a, edit)
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
	n := 0
	for p := range replies {
		if n == 0 {
			edited = p
		}
		if !reflect.DeepEqual(p, edited) {
			t.Error("retries differ")
		}
		n++
	}
	if n != 12 || edited.CurrentVersion != 2 {
		t.Fatalf("replies %d draft %+v", n, edited)
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM operations`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("operations=%d err=%v", count, err)
	}
	op, err := s.LatestReplay(ctx, first.ID, 2)
	if err != nil || op.State != store.OpPending {
		t.Fatal("replay not queued", err)
	}
	audits, err = s.AuditEntries(ctx, 100)
	if err != nil || len(audits) != 3 {
		t.Fatalf("audit count %d %v", len(audits), err)
	}
	if _, err := s.EditPolicyOnce(ctx, first.ID, first.Etag, command, a, edit); !errors.Is(err, store.ErrRequestReused) {
		t.Fatal("queue semantics not bound to request", err)
	}
	cached, err := store.New(pool).GetPolicyReplayEditResult(ctx, first.Etag, command, a)
	if err != nil || !reflect.DeepEqual(cached, edited) {
		t.Fatal("cached reply", err)
	}
	if _, err := s.GetPolicyReplayEditResult(ctx, first.Etag, json.RawMessage(`{"ttl_seconds":7200}`), a); !errors.Is(err, store.ErrRequestReused) {
		t.Fatal("changed command read cached reply", err)
	}
	other := a
	other.Subject = "another-subject"
	if _, err := s.GetPolicyReplayEditResult(ctx, first.Etag, command, other); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("other actor read cached reply", err)
	}
	// Another server retries after a later edit: the exact original draft returns,
	// and neither a third version for this command nor another replay is created.
	later := a
	later.RequestID = "later"
	if _, err := s.UpdatePolicy(ctx, first.ID, edited.Etag, edited.Spec, later); err != nil {
		t.Fatal(err)
	}
	retry, err := store.New(pool).EditPolicyAndReplayOnce(ctx, first.ID, first.Etag, command, a, edit)
	if err != nil || !reflect.DeepEqual(retry, edited) {
		t.Fatal("retry changed result", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM operations`).Scan(&count); err != nil || count != 1 {
		t.Fatal("retry queued twice", err)
	}
}
