package replay

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/strata/strata/control-plane/localauth/localauthtest"
	"github.com/strata/strata/control-plane/store"
)

func TestApprovalBindsReplayInPostgres(t *testing.T) {
	pool := localauthtest.Pool(t)
	s := store.New(pool)
	ctx := t.Context()
	author := store.Audit{Actor: "writer", Subject: "writer", Action: "write", Resource: "policies/example-api"}
	if _, err := s.CreatePolicy(ctx, store.Policy{ID: "example-api", Name: "example-api", Spec: json.RawMessage(`{"mode":"enforce"}`)}, author); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SubmitPolicyVersion(ctx, "example-api", 1, author); err != nil {
		t.Fatal(err)
	}
	queue := func(rep Report) store.Operation {
		op, err := s.CreateReplayOperation(ctx, "example-api", 1, author)
		if err != nil {
			t.Fatal(err)
		}
		claimed, ok, err := s.ClaimOperation(ctx, time.Now().Add(-time.Hour))
		if err != nil || !ok || claimed.ID != op.ID {
			t.Fatal("claim", err)
		}
		raw, err := json.Marshal(rep)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.FinishOperation(ctx, op.ID, raw, ""); err != nil {
			t.Fatal(err)
		}
		return op
	}
	good := Report{InputDigest: digest([]byte("inputs")), DraftSHA256: digest([]byte("draft")), BaselineSHA256: digest([]byte("synthetic baseline")), Corpus: &Route{Samples: 10}}
	old := queue(good)
	approval := store.Audit{Actor: "reviewer", Subject: "reviewer", Action: "approve", Resource: "policies/example-api", ReplayOperation: "missing"}
	if _, err := s.DecidePolicyVersion(ctx, "example-api", 1, true, "ok", approval); err == nil {
		t.Fatal("approved missing proof")
	}
	approval.ReplayOperation = old.ID
	v, err := s.DecidePolicyVersion(ctx, "example-api", 1, true, "ok", approval)
	if err != nil || v.ApprovedReplayID != old.ID {
		t.Fatalf("approval: %+v %v", v, err)
	}
	if err := (Gate{Store: s}).Check(ctx, map[string]int{"example-api": 1}, good.InputDigest); err != nil {
		t.Fatal(err)
	}
	newer := good
	newer.InputDigest = digest([]byte("changed rules"))
	queue(newer)
	// New DONE results cannot replace the report the reviewer approved.
	if err := (Gate{Store: store.New(pool)}).Check(ctx, map[string]int{"example-api": 1}, newer.InputDigest); err == nil {
		t.Fatal("unapproved replay replaced approved proof")
	}
	if err := (Gate{Store: s}).Check(ctx, map[string]int{"example-api": 1}, good.InputDigest); err != nil {
		t.Fatal("old bound proof lost", err)
	}
	b, err := s.RecordBundle(ctx, store.Bundle{InputDigest: good.InputDigest, Version: 1, SHA256: make([]byte, 32), SizeBytes: 1, ObjectKey: "bundle-1", Contents: map[string]int{"example-api": 1}}, author)
	if err != nil {
		t.Fatal(err)
	}
	read, err := s.LatestBundle(ctx)
	if err != nil || read.InputDigest != b.InputDigest {
		t.Fatalf("bundle provenance lost: %+v %v", read, err)
	}
	if err := (Gate{Store: s}).Check(ctx, map[string]int{"example-api": 1}, good.InputDigest); err == nil {
		t.Fatal("changed baseline accepted")
	}
}
