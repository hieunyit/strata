package store_test

import (
	"testing"
	"time"

	"github.com/strata/strata/control-plane/localauth/localauthtest"
	"github.com/strata/strata/control-plane/store"
)

func TestApprovedReplayIsDurableInPostgres(t *testing.T) {
	p := localauthtest.Pool(t)
	s := store.New(p)
	ctx := t.Context()
	writer := store.Audit{Actor: "writer", Subject: "writer"}
	if _, err := s.CreatePolicy(ctx, store.Policy{ID: "example-api", Name: "example-api", Spec: []byte(`{"mode":"shadow"}`)}, writer); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SubmitPolicyVersion(ctx, "example-api", 1, writer); err != nil {
		t.Fatal(err)
	}
	op, err := s.CreateReplayOperation(ctx, "example-api", 1, writer)
	if err != nil {
		t.Fatal(err)
	}
	reviewer := store.Audit{Actor: "reviewer", Subject: "reviewer", ReplayOperation: op.ID}
	if _, err := s.DecidePolicyVersion(ctx, "example-api", 1, true, "ok", reviewer); err == nil {
		t.Fatal("approved PENDING replay")
	}
	if _, ok, err := s.ClaimOperation(ctx, time.Now().Add(-time.Hour)); err != nil || !ok {
		t.Fatal("claim", err)
	}
	if err := s.FinishOperation(ctx, op.ID, []byte(`{"samples":1}`), ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DecidePolicyVersion(ctx, "example-api", 1, true, "ok", reviewer); err != nil {
		t.Fatal(err)
	}
	saved, err := store.New(p).GetPolicyVersion(ctx, "example-api", 1)
	if err != nil || saved.ApprovedReplayID != op.ID {
		t.Fatalf("lost approved proof: %+v %v", saved, err)
	}
	newer, err := s.CreateReplayOperation(ctx, "example-api", 1, writer)
	if err != nil {
		t.Fatal(err)
	}
	if newer.ID == saved.ApprovedReplayID {
		t.Fatal("new operation replaced approved proof")
	}
	saved, err = store.New(p).GetPolicyVersion(ctx, "example-api", 1)
	if err != nil || saved.ApprovedReplayID != op.ID {
		t.Fatal("new replay mutated immutable approval")
	}
}
