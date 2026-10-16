package replay

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/strata/strata/control-plane/policy"
	"github.com/strata/strata/control-plane/store"
)

func TestReplayRecordsPreparedInputs(t *testing.T) {
	r, ops, _ := newRunner(t)
	dir := t.TempDir()
	bin := filepath.Join(dir, "compile")
	if err := os.WriteFile(bin, []byte(`#!/bin/sh
set -eu
while [ $# -gt 0 ]; do
 case "$1" in --out) out=$2;; --rules) rules=$2;; esac
 shift 2
done
cat "$rules" > "$out"
`), 0700); err != nil {
		t.Fatal(err)
	}
	rules := filepath.Join(dir, "rules")
	if err := os.WriteFile(rules, []byte("replayed rules"), 0600); err != nil {
		t.Fatal(err)
	}
	c := &policy.Compiler{Binary: bin, Rules: []string{rules}}
	r.Prepare = c.Prepare
	ops.queue = []store.Operation{{ID: "bound", PolicyID: "example-api", Version: 2}}
	if !r.RunOnce(t.Context()) {
		t.Fatal("no replay")
	}
	var rep Report
	if err := json.Unmarshal([]byte(ops.finished["bound"]), &rep); err != nil {
		t.Fatal(err, ops.finished["bound"])
	}
	if len(rep.InputDigest) != 64 || rep.DraftSHA256 != digest([]byte("replayed rules")) || rep.BaselineSHA256 != digest([]byte("in-force")) || len(rep.ReplaySHA256) != 64 || len(rep.SampleSHA256) != 3 {
		t.Fatalf("missing provenance: %+v", rep)
	}
	if rep.SampleSHA256[0] != digest([]byte("corpus\n")) {
		t.Fatal("corpus hash does not match bytes replayed")
	}
	if err := os.WriteFile(rules, []byte("changed rules"), 0600); err != nil {
		t.Fatal(err)
	}
	ops.queue = []store.Operation{{ID: "changed", PolicyID: "example-api", Version: 2}}
	r.RunOnce(t.Context())
	var changed Report
	if err := json.Unmarshal([]byte(ops.finished["changed"]), &changed); err != nil {
		t.Fatal(err)
	}
	if changed.InputDigest == rep.InputDigest || changed.DraftSHA256 == rep.DraftSHA256 {
		t.Fatal("rule change not reflected in replay provenance")
	}
}
