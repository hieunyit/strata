package replay

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/strata/strata/control-plane/policy"
	"github.com/strata/strata/control-plane/ruleactions"
	"github.com/strata/strata/control-plane/rulecat"
	"github.com/strata/strata/control-plane/store"
)

type fakeOps struct {
	mu       sync.Mutex
	queue    []store.Operation
	finished map[string]string // id -> result or "error: ..."
	versions map[int]json.RawMessage
}

func (f *fakeOps) ClaimOperation(context.Context, time.Time) (store.Operation, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.queue) == 0 {
		return store.Operation{}, false, nil
	}
	o := f.queue[0]
	f.queue = f.queue[1:]
	return o, true, nil
}

func (f *fakeOps) FinishOperation(_ context.Context, id string, res json.RawMessage, msg string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if msg != "" {
		f.finished[id] = "error: " + msg
	} else {
		f.finished[id] = string(res)
	}
	return nil
}

func (f *fakeOps) GetPolicy(_ context.Context, id string) (store.Policy, error) {
	return store.Policy{ID: id, Name: id, CurrentVersion: 2}, nil
}

func (f *fakeOps) GetPolicyVersion(_ context.Context, id string, v int) (store.PolicyVersion, error) {
	spec, ok := f.versions[v]
	if !ok {
		return store.PolicyVersion{}, store.ErrNotFound
	}
	return store.PolicyVersion{PolicyID: id, Version: v, Spec: spec}, nil
}

type fakeObjects map[string][]byte

func (f fakeObjects) List(_ context.Context, prefix string) ([]policy.ObjectInfo, error) {
	var out []policy.ObjectInfo
	for k, v := range f {
		if strings.HasPrefix(k, prefix) {
			out = append(out, policy.ObjectInfo{Key: k, Size: int64(len(v))})
		}
	}
	return out, nil
}

func (f fakeObjects) Get(_ context.Context, key string) ([]byte, error) { return f[key], nil }

// a strata-replay that records its arguments and the bundles it was given
// and prints a comparison like engine/replay's
const fakeReplay = `#!/bin/sh
echo "$@" > "$FAKE_REPLAY_DIR/args"
while [ $# -gt 0 ]; do
  case "$1" in
    --bundle) cp "$2" "$FAKE_REPLAY_DIR/draft.sbn"; shift ;;
    --baseline) cp "$2" "$FAKE_REPLAY_DIR/baseline.sbn"; shift ;;
    --pubkey|--baseline-pubkey|--policy|--threads) shift ;;
    *) cat "$1" >> "$FAKE_REPLAY_DIR/samples" ;;
  esac
  shift
done
if [ -n "$FAKE_REPLAY_FAIL" ]; then echo "strata-replay: $FAKE_REPLAY_FAIL" >&2; exit 1; fi
cat <<'EOF'
{"samples": 12, "elapsed_ms": 7, "routes": {"example-api": {"samples": 10,
 "draft": {"block": 3, "allow": 7}, "baseline": {"block": 1, "allow": 9},
 "newly_blocked": 2, "newly_allowed": 0, "newly_blocked_rules": {"942100": 2},
 "newly_allowed_rules": {}, "newly_blocked_paths": {"/v1/login": 2},
 "newly_blocked_sampled": {"allow": 2}, "newly_allowed_sampled": {},
 "examples_blocked": [{"ts_ms": 1, "node_id": "node-a", "method": "POST", "raw_uri": "/v1/login?u=hmac:ab",
   "draft": "block", "baseline": "allow", "draft_rules": [942100], "baseline_rules": []}],
 "examples_allowed": []}}}
EOF
`

func newRunner(t *testing.T) (*Runner, *fakeOps, string) {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "strata-replay")
	if err := os.WriteFile(bin, []byte(fakeReplay), 0o755); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out")
	if err := os.Mkdir(out, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FAKE_REPLAY_DIR", out)
	corpus := filepath.Join(dir, "corpus.parquet")
	if err := os.WriteFile(corpus, []byte("corpus\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ops := &fakeOps{finished: map[string]string{}, versions: map[int]json.RawMessage{
		2: json.RawMessage(`{"mode":"enforce"}`),
	}}
	now := time.Date(2026, 10, 15, 8, 0, 0, 0, time.UTC)
	r := &Runner{
		Store: ops,
		Deployable: func(context.Context) ([]store.Policy, error) {
			return []store.Policy{
				{ID: "example-api", Name: "example-api", CurrentVersion: 1, Spec: json.RawMessage(`{"mode":"shadow"}`)},
				{ID: "example-web", Name: "example-web", CurrentVersion: 4, Spec: json.RawMessage(`{"mode":"enforce"}`)},
			}, nil
		},
		Build: func(_ context.Context, keyFile string, ps []policy.Named) ([]byte, error) {
			if seed, err := os.ReadFile(keyFile); err != nil || len(seed) != 32 {
				return nil, fmt.Errorf("seed: %v %d", err, len(seed))
			}
			var b strings.Builder
			for _, p := range ps {
				fmt.Fprintf(&b, "%s=%s;", p.Name, p.Spec.Mode)
			}
			return []byte(b.String()), nil
		},
		Baseline:    func(context.Context) ([]byte, uint64, error) { return []byte("in-force"), 41, nil },
		BaselinePub: make([]byte, 32),
		Samples: fakeObjects{
			"replay/v1/example-api/2026/10/15/node-a-1-1.parquet": []byte("today\n"),
			"replay/v1/example-api/2026/10/14/node-a-0-2.parquet": []byte("yesterday\n"),
			"replay/v1/example-api/2026/10/01/node-a-0-3.parquet": []byte("too old\n"),
			"replay/v1/example-web/2026/10/15/node-b-1-4.parquet": []byte("other policy\n"),
		},
		Corpus: corpus,
		Binary: bin,
		Now:    func() time.Time { return now },
	}
	return r, ops, out
}

// W13-G2-01: a queued version is replayed: the draft bundle is what a
// deploy would build with the version (the other policies as they are),
// compared with the bundle in force on the policy's samples of the last 7
// days and on the corpus, apart; the report is stored with the operation.
func TestRunnerReplaysADraft(t *testing.T) {
	r, ops, out := newRunner(t)
	ops.queue = []store.Operation{{ID: "op-1", PolicyID: "example-api", Version: 2}}
	if !r.RunOnce(context.Background()) {
		t.Fatal("nothing run")
	}
	if r.RunOnce(context.Background()) {
		t.Fatal("ran twice")
	}
	var rep Report
	if err := json.Unmarshal([]byte(ops.finished["op-1"]), &rep); err != nil {
		t.Fatalf("%v: %s", err, ops.finished["op-1"])
	}
	if rep.Samples() != 20 || rep.BaselineBundle != 41 || rep.SampleFiles != 2 || rep.Traffic == nil || rep.Corpus == nil || rep.Truncated {
		t.Fatalf("report: %+v", rep)
	}
	rt := rep.Traffic
	if rt.NewlyBlocked != 2 || rt.NewlyBlockedRules["942100"] != 2 || len(rt.ExamplesBlocked) != 1 || rt.ExamplesBlocked[0].DraftRules[0] != 942100 {
		t.Fatalf("route: %+v", rt)
	}
	read := func(name string) string {
		b, err := os.ReadFile(filepath.Join(out, name))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	if got := read("draft.sbn"); got != "example-api=enforce;example-web=enforce;" {
		t.Errorf("draft bundle: %q", got)
	}
	if got := read("baseline.sbn"); got != "in-force" {
		t.Errorf("baseline: %q", got)
	}
	if got := read("samples"); got != "today\nyesterday\ncorpus\n" {
		t.Errorf("samples, newest day first, then the corpus apart: %q", got)
	}
	args := read("args")
	for _, want := range []string{"compare ", "--policy example-api", "--threads 2", "--baseline-pubkey "} {
		if !strings.Contains(args, want) {
			t.Errorf("args lack %q: %s", want, args)
		}
	}
}

// Limits on the traffic samples; no bundle in force yet (the baseline is
// built from the policies without the draft); a new policy no deploy took.
func TestRunnerLimitsAndNothingInForce(t *testing.T) {
	r, ops, out := newRunner(t)
	r.MaxFiles = 1
	r.Baseline = func(context.Context) ([]byte, uint64, error) { return nil, 0, store.ErrNotFound }
	r.Deployable = func(context.Context) ([]store.Policy, error) {
		return []store.Policy{{ID: "example-web", Name: "example-web", Spec: json.RawMessage(`{"mode":"enforce"}`)}}, nil
	}
	ops.queue = []store.Operation{{ID: "op-2", PolicyID: "example-api", Version: 2}}
	r.RunOnce(context.Background())
	var rep Report
	if err := json.Unmarshal([]byte(ops.finished["op-2"]), &rep); err != nil {
		t.Fatalf("%v: %s", err, ops.finished["op-2"])
	}
	if rep.SampleFiles != 1 || !rep.Truncated || rep.BaselineBundle != 0 {
		t.Fatalf("report: %+v", rep)
	}
	b, _ := os.ReadFile(filepath.Join(out, "baseline.sbn"))
	d, _ := os.ReadFile(filepath.Join(out, "draft.sbn"))
	if string(b) != "example-web=enforce;" || string(d) != "example-api=enforce;example-web=enforce;" {
		t.Fatalf("baseline %q, draft %q", b, d)
	}
}

// A failing replay, a missing version and a build error fail the
// operation with the reason.
func TestRunnerFailures(t *testing.T) {
	r, ops, _ := newRunner(t)
	t.Setenv("FAKE_REPLAY_FAIL", "bundle refused (2): bad signature")
	ops.queue = []store.Operation{{ID: "op-3", PolicyID: "example-api", Version: 2},
		{ID: "op-4", PolicyID: "example-api", Version: 7}}
	r.RunOnce(context.Background())
	r.RunOnce(context.Background())
	if got := ops.finished["op-3"]; !strings.Contains(got, "error: strata-replay") || !strings.Contains(got, "bad signature") {
		t.Errorf("op-3: %q", got)
	}
	if got := ops.finished["op-4"]; !strings.Contains(got, "version 7") {
		t.Errorf("op-4: %q", got)
	}
	r.Build = func(context.Context, string, []policy.Named) ([]byte, error) {
		return nil, &policy.CostError{Total: 9, Budget: 1}
	}
	ops.queue = []store.Operation{{ID: "op-5", PolicyID: "example-api", Version: 2}}
	r.RunOnce(context.Background())
	if got := ops.finished["op-5"]; !strings.Contains(got, "building the draft bundle") || !strings.Contains(got, "budget") {
		t.Errorf("op-5: %q", got)
	}
}

// Run picks up an operation queued while it waits, when kicked.
func TestRunnerKick(t *testing.T) {
	r, ops, _ := newRunner(t)
	r.Poll = time.Hour
	if err := r.Init(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = r.Run(ctx); close(done) }()
	ops.mu.Lock()
	ops.queue = append(ops.queue, store.Operation{ID: "op-6", PolicyID: "example-api", Version: 2})
	ops.mu.Unlock()
	r.Kick()
	deadline := time.Now().Add(10 * time.Second)
	for {
		ops.mu.Lock()
		_, ok := ops.finished["op-6"]
		ops.mu.Unlock()
		if ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("not run after a kick")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
}

// RS-5: the report lists the rules whose action the draft changes against
// the version in force, whatever the traffic.
func TestRunnerListsRuleActionChanges(t *testing.T) {
	r, ops, _ := newRunner(t)
	dir := t.TempDir()
	f := filepath.Join(dir, "rules.yaml")
	ir := `ir_version: 1
ruleset: { name: example, version: "1" }
rules:
  - { id: 500100, name: Known scanner user agent, layer: managed, metadata: { source: crawler-user-agents, attack_type: scanner, tags: [scanner] } }
  - { id: 942100, name: SQL injection via libinjection, layer: managed, metadata: { source: crs, attack_type: sql-injection } }
`
	if err := os.WriteFile(f, []byte(ir), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := rulecat.Load([]string{f})
	if err != nil {
		t.Fatal(err)
	}
	r.Catalog = func() *rulecat.Catalog { return c }
	// in force: scanners logged (version 1); the draft blocks them and
	// switches 942100 off
	r.Deployable = func(context.Context) ([]store.Policy, error) {
		return []store.Policy{{ID: "example-api", Name: "example-api", CurrentVersion: 1,
			Spec: json.RawMessage(`{"mode":"enforce","rule_sets":[{"set":"bots-scanners","action":"log"}]}`)}}, nil
	}
	ops.versions[2] = json.RawMessage(`{"mode":"enforce","rule_sets":[{"set":"bots-scanners","action":"block"}],"rule_overrides":[{"rule":942100,"action":"off","reason":"FP"}]}`)
	ops.queue = []store.Operation{{ID: "op-ra", PolicyID: "example-api", Version: 2}}
	r.RunOnce(context.Background())
	var rep Report
	if err := json.Unmarshal([]byte(ops.finished["op-ra"]), &rep); err != nil {
		t.Fatalf("%v: %s", err, ops.finished["op-ra"])
	}
	want := []ruleactions.Change{
		{Rule: 500100, Name: "Known scanner user agent", From: "log", To: "block", Source: "set", Set: "bots-scanners"},
		{Rule: 942100, Name: "SQL injection via libinjection", From: "score", To: "off", Source: "override"},
	}
	if rep.RuleActions == nil || rep.RuleActions.Changed != 2 || !reflect.DeepEqual(rep.RuleActions.Rules, want) {
		t.Fatalf("rule actions %+v", rep.RuleActions)
	}
	// without a catalog: none
	r.Catalog = func() *rulecat.Catalog { return nil }
	ops.queue = []store.Operation{{ID: "op-rb", PolicyID: "example-api", Version: 2}}
	r.RunOnce(context.Background())
	if strings.Contains(ops.finished["op-rb"], "rule_actions") {
		t.Fatalf("rule actions without a catalog: %s", ops.finished["op-rb"])
	}
}
