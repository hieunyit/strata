package policy

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/strata/strata/control-plane/store"
)

func TestDeployChecksReplayBeforePublishing(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "compiler")
	if err := os.WriteFile(bin, []byte(`#!/bin/sh
set -eu
while [ $# -gt 0 ]; do
 case "$1" in --out) out=$2;; --rules) rules=$2;; --key) fixture=$2;; esac
 shift 2
done
grep -q '^original$' "$rules"
cp "$fixture" "$out"
`), 0700); err != nil {
		t.Fatal(err)
	}
	rules := filepath.Join(dir, "rules")
	if err := os.WriteFile(rules, []byte("original\n"), 0600); err != nil {
		t.Fatal(err)
	}
	fixture := filepath.Join(dir, "signed.sbn")
	if err := os.WriteFile(fixture, signed(priv, 1, 1), 0600); err != nil {
		t.Fatal(err)
	}
	compiler := &Compiler{Binary: bin, Rules: []string{rules}, KeyFile: fixture}
	named := []Named{{Name: "example-api", Spec: Spec{Mode: "enforce"}}}
	prepared, err := compiler.Prepare(t.Context(), named)
	if err != nil {
		t.Fatal(err)
	}
	digest := prepared.Digest
	prepared.Close()
	ps := []store.Policy{{ID: "api", Name: "example-api", CurrentVersion: 1, Spec: json.RawMessage(`{"mode":"enforce"}`)}}
	for _, allowed := range []bool{false, true} {
		st := &fakeStore{policies: ps}
		obj := &fakeObjects{puts: map[string][]byte{}}
		checked := false
		d := &Deployer{Store: st, Builder: compiler, Objects: obj, PubKey: pub, VerifyReplay: func(_ context.Context, contents map[string]int, got string) error {
			checked = true
			if got != digest || contents["api"] != 1 {
				t.Fatal("gate got different inputs")
			}
			if !allowed {
				return &ReplayError{Msg: "old replay"}
			}
			// A rule replacement after checking must not affect bytes compiled next.
			return os.WriteFile(rules, []byte("changed after verification\n"), 0600)
		}}
		dep, err := d.Deploy(t.Context(), store.Audit{Actor: "operator"})
		if !checked {
			t.Fatal("replay gate bypassed")
		}
		if !allowed {
			var mismatch *ReplayError
			if !errors.As(err, &mismatch) || len(obj.puts) != 0 || len(st.bundles) != 0 {
				t.Fatalf("rejected deploy published: %v", err)
			}
		} else if err != nil || dep.Bundle.InputDigest != digest || len(obj.puts) != 1 {
			t.Fatalf("snapshot deploy: %+v %v", dep, err)
		}
	}
}
