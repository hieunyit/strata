package replay

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/strata/strata/control-plane/policy"
	"github.com/strata/strata/control-plane/store"
)

// W13-G2-01 with the real binaries (STRATA_TEST_REPLAY_BIN = strata-replay,
// STRATA_TEST_COMPILER = strata-compile, both from one build): the draft
// turns example-api from shadow to enforce; the corpus attacks the CRS rules
// catch are newly blocked, and the run fails cleanly on a baseline signed
// with another key.
func TestRealReplay(t *testing.T) {
	bin, compiler := os.Getenv("STRATA_TEST_REPLAY_BIN"), os.Getenv("STRATA_TEST_COMPILER")
	if bin == "" || compiler == "" {
		t.Skip("STRATA_TEST_REPLAY_BIN and STRATA_TEST_COMPILER not set")
	}
	repo, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	corpus := filepath.Join(dir, "corpus.parquet")
	if out, err := exec.Command(bin, "gen", "--out", corpus, "--count", "4300", "--corpus", filepath.Join(repo, "corpus")).CombinedOutput(); err != nil {
		t.Fatalf("gen: %v: %s", err, out)
	}
	rules, err := filepath.Glob(filepath.Join(repo, "rules/crs/*.yaml"))
	if err != nil || len(rules) == 0 {
		t.Fatalf("rules: %v %v", rules, err)
	}
	c := policy.Compiler{Binary: compiler, Rules: rules, CostBudget: 0}
	ops := &fakeOps{finished: map[string]string{}, versions: map[int]json.RawMessage{2: json.RawMessage(`{"mode":"enforce"}`)}}
	r := &Runner{
		Store: ops,
		Deployable: func(context.Context) ([]store.Policy, error) {
			return []store.Policy{{ID: "example-api", Name: "example-api", CurrentVersion: 1, Spec: json.RawMessage(`{"mode":"shadow"}`)}}, nil
		},
		Build:    ReplayBuilder(c),
		Prepare:  c.Prepare,
		Baseline: func(context.Context) ([]byte, uint64, error) { return nil, 0, store.ErrNotFound },
		Corpus:   corpus,
		Binary:   bin,
		Timeout:  5 * time.Minute,
	}
	ops.queue = []store.Operation{{ID: "op-real", PolicyID: "example-api", Version: 2}}
	r.RunOnce(context.Background())
	var rep Report
	if err := json.Unmarshal([]byte(ops.finished["op-real"]), &rep); err != nil {
		t.Fatalf("%v: %s", err, ops.finished["op-real"])
	}
	for name, digest := range map[string]string{"inputs": rep.InputDigest, "draft": rep.DraftSHA256, "baseline": rep.BaselineSHA256, "replay": rep.ReplaySHA256} {
		if len(digest) != 64 {
			t.Fatalf("missing real snapshot digest %s: %q", name, digest)
		}
	}
	if len(rep.SampleSHA256) == 0 {
		t.Fatal("missing corpus digest")
	}
	for _, digest := range rep.SampleSHA256 {
		if len(digest) != 64 {
			t.Fatal("invalid corpus digest")
		}
	}
	rt := rep.Corpus
	if rep.Samples() != 4300 || rep.Traffic != nil || rt == nil || rt.NewlyBlocked == 0 || rt.NewlyAllowed != 0 || len(rt.NewlyBlockedRules) == 0 {
		t.Fatalf("report: %+v, corpus %+v", rep, rt)
	}
	t.Logf("4300 corpus samples: %d newly blocked by %d rules in %d ms", rt.NewlyBlocked, len(rt.NewlyBlockedRules), rep.ElapsedMs)

	// a bundle in force that does not verify with BaselinePub
	other := ed25519.NewKeyFromSeed(make([]byte, 32))
	seed := filepath.Join(dir, "other.seed")
	if err := os.WriteFile(seed, other.Seed(), 0o600); err != nil {
		t.Fatal(err)
	}
	inForce, err := ReplayBuilder(c)(context.Background(), seed, []policy.Named{{Name: "example-api", Spec: policy.Spec{Mode: "shadow"}}})
	if err != nil {
		t.Fatal(err)
	}
	r.Baseline = func(context.Context) ([]byte, uint64, error) { return inForce, 7, nil }
	r.BaselinePub = make([]byte, 32)
	ops.queue = []store.Operation{{ID: "op-bad", PolicyID: "example-api", Version: 2}}
	r.RunOnce(context.Background())
	if got := ops.finished["op-bad"]; len(got) < 7 || got[:7] != "error: " {
		t.Fatalf("baseline with a wrong key: %q", got)
	}
}
