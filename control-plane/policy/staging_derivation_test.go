package policy

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStagingDerivationIsAdditiveAndSourceBound(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "compiler")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	c := Compiler{Binary: bin}
	ps := []Named{{Name: "example-api", Spec: Spec{Mode: "enforce", AutoStaging: exampleAutoStaging()}}}
	p, err := c.Prepare(t.Context(), ps)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	source := p.Digest
	p.Digest = strings.Repeat("a", 64)
	if err := p.addStagedRules(p.Digest, "example-api", []uint32{700011}); !errors.Is(err, ErrStagingSourceMismatch) {
		t.Fatalf("public digest spoof accepted: %v", err)
	}
	p.Digest = source
	if err := p.addStagedRules("wrong", "example-api", []uint32{700011}); !errors.Is(err, ErrStagingSourceMismatch) {
		t.Fatalf("stale source: %v", err)
	}
	if p.Digest != source {
		t.Fatal("rejected derivation mutated digest")
	}
	for _, ids := range [][]uint32{nil, {42}, {700011, 700011}} {
		if err := p.addStagedRules(source, "example-api", ids); err == nil {
			t.Fatalf("invalid addition accepted: %v", ids)
		}
	}
	if err := p.addStagedRules(source, "other-api", []uint32{700011}); err == nil {
		t.Fatal("unknown policy accepted")
	}
	if err := p.addStagedRules(source, "example-api", []uint32{700011}); err != nil {
		t.Fatal(err)
	}
	first := p.Digest
	if first == source {
		t.Fatal("overlay not bound into derived digest")
	}
	// The new digest must equal a freshly captured exact effective input set,
	// not an arbitrary hash of the delta detached from compiler/rule inputs.
	c.StagedRules = map[string][]uint32{"example-api": {700011}}
	fresh, err := c.Prepare(t.Context(), ps)
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	if fresh.Digest != first {
		t.Fatal("derived digest does not describe full effective inputs")
	}
	if err := p.addStagedRules(source, "example-api", []uint32{942100}); !errors.Is(err, ErrStagingSourceMismatch) {
		t.Fatalf("old parent reused: %v", err)
	}
	if err := p.addStagedRules(first, "example-api", []uint32{942100}); err != nil {
		t.Fatal(err)
	}
	second := p.Digest
	if second == first || len(p.compiler.StagedRules["example-api"]) != 2 {
		t.Fatal("addition lost previous staged rule")
	}
	if err := p.addStagedRules(second, "example-api", []uint32{700011}); err != nil || p.Digest != second {
		t.Fatalf("idempotent addition: %v", err)
	}
	if err := p.addStagedRules(second, "example-api", []uint32{42}); err == nil || p.Digest != second || len(p.compiler.StagedRules["example-api"]) != 2 {
		t.Fatal("failed addition partially mutated snapshot")
	}
	if err := (*Prepared)(nil).addStagedRules(second, "example-api", []uint32{700011}); !errors.Is(err, ErrStagingSourceMismatch) {
		t.Fatal(err)
	}
}
