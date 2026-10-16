package policy

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/strata/strata/control-plane/store"
)

// TestCostBudgetThresholdBoundary tests exact boundaries:
// cost < budget: passes
// cost == budget: boundary passes
// cost > budget: fails with CostError
func TestCostBudgetThresholdBoundary(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "fake-compile")
	_ = os.WriteFile(script, []byte(`#!/bin/sh
while [ $# -gt 0 ]; do
  case "$1" in
    --out) printf testbundle > "$2"; shift 2 ;;
    --cost-report)
      printf '{"total":10000,"rules":[{"id":942100,"name":"SQLi","cost":6000},{"id":941100,"name":"XSS","cost":4000}]}' > "$2"
      shift 2 ;;
    *) shift ;;
  esac
done
`), 0o755)

	// Case 1: cost (10000) > budget (9999) -> must fail with CostError
	cOver := &Compiler{Binary: script, KeyFile: "/keys/seed", CostBudget: 9999}
	_, errOver := cOver.Build(context.Background(), 1, []Named{{Name: "example-api", Spec: Spec{Mode: "enforce"}}})
	var ce *CostError
	if !errors.As(errOver, &ce) {
		t.Fatalf("expected CostError, got %v", errOver)
	}
	if ce.Total != 10000 || ce.Budget != 9999 || len(ce.Top) != 2 {
		t.Fatalf("unexpected CostError values: %+v", ce)
	}

	// Case 2: cost (10000) == budget (10000) -> exact boundary must pass
	cExact := &Compiler{Binary: script, KeyFile: "/keys/seed", CostBudget: 10000}
	outExact, errExact := cExact.Build(context.Background(), 1, []Named{{Name: "example-api", Spec: Spec{Mode: "enforce"}}})
	if errExact != nil || string(outExact) != "testbundle" {
		t.Fatalf("at exact budget expected success, got out=%q err=%v", outExact, errExact)
	}

	// Case 3: cost (10000) < budget (10001) -> must pass
	cUnder := &Compiler{Binary: script, KeyFile: "/keys/seed", CostBudget: 10001}
	outUnder, errUnder := cUnder.Build(context.Background(), 1, []Named{{Name: "example-api", Spec: Spec{Mode: "enforce"}}})
	if errUnder != nil || string(outUnder) != "testbundle" {
		t.Fatalf("under budget expected success, got out=%q err=%v", outUnder, errUnder)
	}
}

// TestDeployRollbackOnCostOverflow verifies that if bundle cost exceeds budget,
// Deploy fails with CostError, object store receives 0 puts, and store records 0 bundles (clean rollback).
func TestDeployRollbackOnCostOverflow(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	pols := []store.Policy{
		{ID: "api", Name: "example-api", CurrentVersion: 1, Spec: []byte(`{"mode":"enforce"}`)},
	}

	st := &fakeStore{policies: pols}
	obj := &fakeObjects{puts: map[string][]byte{}}

	// Create custom Builder implementation that returns CostError
	builderWithCostError := &costErrorBuilder{
		err: &CostError{
			Total:  75000,
			Budget: 50000,
			Top: []RuleCost{
				{ID: 942100, Name: "SQLi", Cost: 30000},
			},
		},
	}

	d := &Deployer{
		Store:   st,
		Builder: builderWithCostError,
		Objects: obj,
		PubKey:  pub,
	}

	dep, err := d.Deploy(context.Background(), store.Audit{Actor: "operator"})
	if err == nil {
		t.Fatal("expected deploy to fail on cost budget overflow")
	}

	var ce *CostError
	if !errors.As(err, &ce) {
		t.Fatalf("expected CostError, got %v", err)
	}
	if ce.Total != 75000 || ce.Budget != 50000 {
		t.Fatalf("unexpected cost error fields: %+v", ce)
	}

	// Verify Rollback: nothing was put in objects, no bundle recorded in store
	if len(obj.puts) != 0 {
		t.Fatalf("rollback failed: object store has %d puts", len(obj.puts))
	}
	if len(st.bundles) != 0 {
		t.Fatalf("rollback failed: store recorded %d bundles", len(st.bundles))
	}
	if dep.Bundle.Version != 0 {
		t.Fatalf("unexpected deployment bundle: %+v", dep.Bundle)
	}
}

type costErrorBuilder struct {
	err error
}

func (c *costErrorBuilder) Build(_ context.Context, _ uint64, _ []Named) ([]byte, error) {
	return nil, c.err
}

// TestDeployRollbackOnCorruptedBundle verifies that when bundle signature or format is corrupted,
// Deploy fails verification and rolls back with 0 published objects.
func TestDeployRollbackOnCorruptedBundle(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	pols := []store.Policy{
		{ID: "api", Name: "example-api", CurrentVersion: 1, Spec: []byte(`{"mode":"enforce"}`)},
	}

	st := &fakeStore{policies: pols}
	obj := &fakeObjects{puts: map[string][]byte{}}

	// Builder returns garbage corrupted bytes
	corruptedBuilder := builderFunc(func(_ uint64, _ int) []byte {
		return []byte("GARBAGE_BUNDLE_DATA_NOT_VALID")
	})

	d := &Deployer{
		Store:   st,
		Builder: corruptedBuilder,
		Objects: obj,
		PubKey:  pub,
	}

	_, err := d.Deploy(context.Background(), store.Audit{Actor: "operator"})
	if err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Fatalf("expected verification error, got: %v", err)
	}

	// Verify Rollback
	if len(obj.puts) != 0 {
		t.Fatalf("rollback failed: corrupted bundle was written to object store")
	}
	if len(st.bundles) != 0 {
		t.Fatalf("rollback failed: corrupted bundle was recorded in store")
	}
}
