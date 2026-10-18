package policy

import (
	"context"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"testing"
)

type stagingReaderFunc func(context.Context, map[string]int) (map[string][]uint32, error)

func (f stagingReaderFunc) StagedRules(c context.Context, v map[string]int) (map[string][]uint32, error) {
	return f(c, v)
}

func TestVersionedStagingCapture(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "compiler")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	ps := []Named{{ResourceID: "policy-resource", Version: 3, Name: "example-api", Spec: Spec{Mode: "enforce", AutoStaging: exampleAutoStaging()}}}
	rules := []uint32{942100}
	calls := 0
	c := Compiler{Binary: bin, StagingStore: stagingReaderFunc(func(ctx context.Context, v map[string]int) (map[string][]uint32, error) {
		calls++
		if !maps.Equal(v, map[string]int{"policy-resource": 3}) {
			t.Fatalf("wrong versions: %v", v)
		}
		return map[string][]uint32{"policy-resource": rules}, nil
	})}
	captured, err := c.Prepare(t.Context(), ps)
	if err != nil {
		t.Fatal(err)
	}
	defer captured.Close()
	explicit := Compiler{Binary: bin, StagedRules: map[string][]uint32{"example-api": {942100}}}
	expected, err := explicit.Prepare(t.Context(), ps)
	if err != nil {
		t.Fatal(err)
	}
	defer expected.Close()
	if captured.Digest != expected.Digest || captured.compiler.StagingStore != nil || calls != 1 {
		t.Fatal("durable overlay not captured exactly once")
	}
	rules[0] = 942101
	if captured.compiler.StagedRules["example-api"][0] != 942100 || len(c.StagedRules) != 0 {
		t.Fatal("shared state mutated captured inputs or compiler")
	}
	// Metadata is not compiler input. Replay Gate independently binds resource
	// versions; changing a version selects a new state set instead of carrying old IDs.
	ps[0].Version = 4
	ps[0].Spec.AutoStaging = nil
	c.StagingStore = stagingReaderFunc(func(ctx context.Context, v map[string]int) (map[string][]uint32, error) {
		if v["policy-resource"] != 4 {
			t.Fatal(v)
		}
		return nil, nil
	})
	fresh, err := c.Prepare(t.Context(), ps)
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	if len(fresh.compiler.StagedRules) != 0 || fresh.Digest == captured.Digest {
		t.Fatal("old version state carried into new candidate")
	}
	// With no ledger state, resource metadata alone changes no bundle digest.
	plain := c
	plain.StagingStore = nil
	baseline, err := plain.Prepare(t.Context(), ps)
	if err != nil {
		t.Fatal(err)
	}
	defer baseline.Close()
	if baseline.Digest != fresh.Digest {
		t.Fatal("empty-state compatibility lost")
	}
}

func TestVersionedStagingRejectsIncompleteOrUntrustedState(t *testing.T) {
	ps := []Named{{ResourceID: "id", Version: 1, Name: "example-api", Spec: Spec{Mode: "enforce", AutoStaging: exampleAutoStaging()}}}
	sentinel := errors.New("storage unavailable")
	c := Compiler{StagingStore: stagingReaderFunc(func(context.Context, map[string]int) (map[string][]uint32, error) { return nil, sentinel })}
	if _, err := c.Prepare(t.Context(), ps); !errors.Is(err, sentinel) {
		t.Fatalf("read failure hidden: %v", err)
	}
	calls := 0
	c.StagingStore = stagingReaderFunc(func(context.Context, map[string]int) (map[string][]uint32, error) { calls++; return nil, nil })
	for _, bad := range [][]Named{{{Name: "example-api", Version: 1}}, {{Name: "example-api", ResourceID: "id"}}, {ps[0], ps[0]}} {
		if _, err := c.Prepare(t.Context(), bad); err == nil {
			t.Fatal("incomplete/duplicate resource accepted")
		}
	}
	if calls != 0 {
		t.Fatal("invalid resources queried store")
	}
	c.StagedRules = map[string][]uint32{"example-api": {942100}}
	if _, err := c.Prepare(t.Context(), ps); err == nil {
		t.Fatal("manual overlay replaced durable state")
	}
	c.StagedRules = nil
	for _, state := range []map[string][]uint32{{"other-id": {942100}}, {"id": {1}}, {"id": {942100, 942100}}} {
		c.StagingStore = stagingReaderFunc(func(context.Context, map[string]int) (map[string][]uint32, error) { return state, nil })
		if _, err := c.Build(t.Context(), 1, ps); err == nil {
			t.Fatalf("bad state accepted: %v", state)
		}
	}
}
