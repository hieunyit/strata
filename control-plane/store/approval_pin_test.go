package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/strata/strata/control-plane/localauth/localauthtest"
	"github.com/strata/strata/control-plane/store"
)

func TestApprovalRejectsReplacedReplayInPostgres(t *testing.T) {
	p := localauthtest.Pool(t)
	s, ctx := store.New(p), t.Context()
	author := store.Audit{Actor: "author", Subject: "author"}
	if _, err := s.CreatePolicy(ctx, store.Policy{ID: "example-api", Name: "example-api", Spec: []byte(`{"mode":"shadow"}`)}, author); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SubmitPolicyVersion(ctx, "example-api", 1, author); err != nil {
		t.Fatal(err)
	}
	done := func() store.Operation {
		t.Helper()
		op, err := s.CreateReplayOperation(ctx, "example-api", 1, author)
		if err != nil {
			t.Fatal(err)
		}
		claimed, ok, err := s.ClaimOperation(ctx, time.Now().Add(-time.Hour))
		if err != nil || !ok || claimed.ID != op.ID {
			t.Fatal("claim", err)
		}
		if err = s.FinishOperation(ctx, op.ID, []byte(`{"samples":1}`), ""); err != nil {
			t.Fatal(err)
		}
		return op
	}
	a, b := done(), done()
	before, err := s.AuditEntries(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	reviewer := store.Audit{Actor: "reviewer", Subject: "reviewer", ReplayOperation: a.ID}
	if _, err = s.DecidePolicyVersion(ctx, "example-api", 1, true, "", reviewer); err == nil {
		t.Fatal("approved superseded replay")
	}
	saved, err := s.GetPolicyVersion(ctx, "example-api", 1)
	if err != nil || saved.State != store.VersionSubmitted || saved.ApprovedReplayID != "" {
		t.Fatal("failed approval mutated version", saved, err)
	}
	after, err := s.AuditEntries(ctx, 100)
	if err != nil || len(after) != len(before) {
		t.Fatal("failed approval wrote audit", err)
	}
	reviewer.ReplayOperation = b.ID
	if _, err = s.DecidePolicyVersion(ctx, "example-api", 1, true, "", reviewer); err != nil {
		t.Fatal(err)
	}
	saved, err = s.GetPolicyVersion(ctx, "example-api", 1)
	if err != nil || saved.ApprovedReplayID != b.ID {
		t.Fatal("wrong saved proof", err)
	}
}

// Hold a real version lock, observe a second PostgreSQL session waiting,
// then replace the replay while the decision is blocked. No timing-only
// assertion: the API's captured proof must be rechecked after this wait.
func TestApprovalAndReplaySerializeInPostgres(t *testing.T) {
	p := localauthtest.Pool(t)
	s := store.New(p)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	author := store.Audit{Actor: "author", Subject: "author"}
	if _, err := s.CreatePolicy(ctx, store.Policy{ID: "example-api", Name: "example-api", Spec: []byte(`{}`)}, author); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SubmitPolicyVersion(ctx, "example-api", 1, author); err != nil {
		t.Fatal(err)
	}
	op, err := s.CreateReplayOperation(ctx, "example-api", 1, author)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, err := s.ClaimOperation(ctx, time.Now().Add(-time.Hour)); err != nil || !ok {
		t.Fatal(err)
	}
	if err = s.FinishOperation(ctx, op.ID, []byte(`{"samples":1}`), ""); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"queue", "approve"} {
		t.Run(kind, func(t *testing.T) {
			tx, err := p.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(context.Background()) }()
			var pid int
			if err = tx.QueryRow(ctx, `SELECT pg_backend_pid() FROM policy_versions WHERE policy_id='example-api' AND version=1 FOR UPDATE`).Scan(&pid); err != nil {
				t.Fatal(err)
			}
			result := make(chan error, 1)
			go func() {
				if kind == "queue" {
					_, e := s.CreateReplayOperation(ctx, "example-api", 1, author)
					result <- e
					return
				}
				_, e := s.DecidePolicyVersion(ctx, "example-api", 1, true, "", store.Audit{Actor: "reviewer", Subject: "reviewer", ReplayOperation: op.ID})
				result <- e
			}()
			for {
				var blocked bool
				if err = p.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND $1=ANY(pg_blocking_pids(pid)))`, pid).Scan(&blocked); err != nil {
					t.Fatal(err)
				}
				if blocked {
					break
				}
				select {
				case err := <-result:
					t.Fatalf("%s bypassed version lock: %v", kind, err)
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				case <-time.After(5 * time.Millisecond):
				}
			}
			var unlockedAfter time.Time
			if err = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&unlockedAfter); err != nil {
				t.Fatal(err)
			}
			if err = tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			err = <-result
			if kind == "queue" {
				if err != nil {
					t.Fatal(err)
				}
				latest, err := s.LatestReplay(ctx, "example-api", 1)
				if err != nil || latest.CreatedAt.Before(unlockedAfter) {
					t.Fatal("queue used pre-lock transaction timestamp", latest.CreatedAt, err)
				}
			}
			var stateErr *store.StateError
			if kind == "approve" && !errors.As(err, &stateErr) {
				t.Fatalf("stale proof accepted after lock wait: %v", err)
			}
		})
	}
	t.Log("PASS: queue and approval wait on the same version; stale proof rejected after wait")
}
