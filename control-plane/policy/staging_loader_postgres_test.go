package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/strata/strata/control-plane/localauth/localauthtest"
	"github.com/strata/strata/control-plane/store"
)

// Digest/state boundary only; real compiler/signature and actual HTTP overlay
// behavior have separate tests. No claim of rollout or node activation here.
func TestStagingLedgerFeedsExactVersionSnapshot(t *testing.T) {
	pool := localauthtest.Pool(t)
	s := store.New(pool)
	ctx := t.Context()
	author := store.Audit{Actor: "operator", Subject: "operator"}
	p, err := s.CreatePolicy(ctx, store.Policy{ID: "example-api", Name: "example-api", Spec: []byte(`{"mode":"enforce","auto_staging":{"enabled":true,"rule_ids":[700011],"window_seconds":300,"min_matches":100,"min_reports":5,"fp_threshold_bps":500}}`)}, author)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.SubmitPolicyVersion(ctx, p.ID, 1, author); err != nil {
		t.Fatal(err)
	}
	if _, err = s.DecidePolicyVersion(ctx, p.ID, 1, true, "", store.Audit{Actor: "approver", Subject: "approver"}); err != nil {
		t.Fatal(err)
	}
	spec, err := Parse(p.Spec)
	if err != nil {
		t.Fatal(err)
	}
	named := []Named{{ResourceID: p.ID, Version: 1, Name: p.Name, Spec: spec}}
	binary := filepath.Join(t.TempDir(), "compiler")
	if err = os.WriteFile(binary, []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	c := Compiler{Binary: binary, StagingStore: s}
	before, err := c.Prepare(ctx, named)
	if err != nil {
		t.Fatal(err)
	}
	defer before.Close()
	source := store.Bundle{Version: 1, InputDigest: before.Digest, SHA256: []byte(strings.Repeat("a", 32)), ObjectKey: "bundles/1", SizeBytes: 100, Contents: map[string]int{p.ID: 1}}
	if source, err = s.RecordBundle(ctx, source, author); err != nil {
		t.Fatal(err)
	}
	if err = before.addStagedRules(source.InputDigest, p.Name, []uint32{700011}); err != nil {
		t.Fatal(err)
	}
	derived := source
	derived.Version = 2
	derived.InputDigest = before.Digest
	derived.ObjectKey = "bundles/2"
	derived.SHA256 = []byte(strings.Repeat("b", 32))
	now := time.Date(2026, 10, 17, 1, 0, 0, 0, time.UTC)
	if _, err = s.RecordStagingBundle(ctx, source, derived, store.StagingAction{ID: "example-action", PolicyID: p.ID, PolicyVersion: 1, RuleID: 700011, Matches: 100, Reports: 5, WindowFrom: now.Add(-5 * time.Minute), WindowTo: now}, store.Audit{Actor: "worker", Channel: "system"}); err != nil {
		t.Fatal(err)
	}
	// Reconstruct exactly the same derived inputs from another Store/compiler.
	c.StagingStore = store.New(pool)
	restarted, err := c.Prepare(ctx, named)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	if restarted.Digest != derived.InputDigest || restarted.compiler.StagedRules[p.Name][0] != 700011 {
		t.Fatal("restart lost effective digest/state")
	}
	// A new human draft can remove opt-in, but gets no old-version stage state.
	// It still must replay and obtain independent approval before deployment.
	if _, err = s.UpdatePolicy(ctx, p.ID, p.Etag, []byte(`{"mode":"enforce"}`), author); err != nil {
		t.Fatal(err)
	}
	named[0].Version = 2
	named[0].Spec = Spec{Mode: "enforce"}
	draft, err := c.Prepare(ctx, named)
	if err != nil {
		t.Fatal(err)
	}
	defer draft.Close()
	if len(draft.compiler.StagedRules) != 0 || draft.Digest == restarted.Digest {
		t.Fatal("candidate reused previous version state")
	}
	approved, err := s.DeployablePolicies(ctx)
	if err != nil || len(approved) != 1 || approved[0].CurrentVersion != 1 {
		t.Fatalf("draft replaced authority: %v %v", approved, err)
	}
}
