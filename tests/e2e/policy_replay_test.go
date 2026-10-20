package e2e

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/strata/strata/control-plane/admin"
	"github.com/strata/strata/control-plane/api"
	"github.com/strata/strata/control-plane/auth"
	"github.com/strata/strata/control-plane/auth/authtest"
	"github.com/strata/strata/control-plane/db"
	"github.com/strata/strata/control-plane/ingest"
	"github.com/strata/strata/control-plane/policy"
	"github.com/strata/strata/control-plane/replay"
	"github.com/strata/strata/control-plane/store"
)

// fakeReplay stands in for strata-replay compare (no Rust toolchain here):
// it checks that it got the draft, the baseline and the sample file from
// object storage, and prints one route. The real chain runs in
// control-plane/replay (TestRealReplay, with the binaries).
const fakeReplay = `#!/bin/sh
case "$*" in
  *"--policy example-api"*) ;;
  *) echo "no --policy: $*" >&2; exit 1 ;;
esac
n=0
for a in "$@"; do case "$a" in *.parquet) n=$((n+1)); grep -q sample-bytes "$a" || { echo "bad sample $a" >&2; exit 1; } ;; esac; done
[ "$n" = 1 ] || { echo "want 1 sample file, got $n" >&2; exit 1; }
cat <<'EOF'
{"samples": 5, "elapsed_ms": 3, "routes": {"example-api": {"samples": 5, "draft": {"block": 2, "allow": 3},
 "baseline": {"allow": 5}, "newly_blocked": 2, "newly_allowed": 0, "newly_blocked_rules": {"942100": 2},
 "newly_allowed_rules": {}, "newly_blocked_paths": {"/v1/login": 2}, "newly_blocked_sampled": {"allow": 2},
 "newly_allowed_sampled": {}, "examples_blocked": [{"ts_ms": 1, "node_id": "node-a", "method": "GET",
 "raw_uri": "/v1/login?u=hmac:ab", "draft": "block", "baseline": "allow", "draft_rules": [942100], "baseline_rules": []}],
 "examples_allowed": []}}}
EOF
`

// W13-G2-01 "Xong khi": a draft is made (a policy created or edited) → its
// replay runs on its own → the result is read through the API; and
// POST :replay queues another one.
func TestPolicyDraftReplay(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pool := startPostgres(t)
	latest, _ := db.Latest()
	if err := db.Migrate(ctx, pool, latest); err != nil {
		t.Fatal(err)
	}
	st := store.New(pool)
	objects, err := artifactStore(ctx, t)
	if err != nil {
		t.Fatal(err)
	}
	today := time.Now().UTC()
	key := fmt.Sprintf("replay/v1/example-api/%04d/%02d/%02d/node-a-1-1.parquet", today.Year(), today.Month(), today.Day())
	if err := objects.Put(ctx, key, []byte("sample-bytes"), ""); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(t.TempDir(), "strata-replay")
	if err := os.WriteFile(bin, []byte(fakeReplay), 0o755); err != nil {
		t.Fatal(err)
	}
	seed := make([]byte, ed25519.SeedSize)
	copy(seed, "e2e-bundle-signing-seed-32-bytes")
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	keyfile := filepath.Join(t.TempDir(), "deploy.seed")
	if err := os.WriteFile(keyfile, seed, 0600); err != nil {
		t.Fatal(err)
	}
	rules := filepath.Join(t.TempDir(), "rules.json")
	if err := os.WriteFile(rules, []byte("original rules"), 0600); err != nil {
		t.Fatal(err)
	}
	compiler := &policy.Compiler{Binary: buildFakeCompiler(t), KeyFile: keyfile, Rules: []string{rules}}
	deployer := &policy.Deployer{Store: st, Builder: compiler, Objects: objects, PubKey: pub, VerifyReplay: (replay.Gate{Store: st}).Check}
	runner := &replay.Runner{Prepare: compiler.Prepare, Store: st, Deployable: st.DeployablePolicies,
		Build:       replay.ReplayBuilder(*compiler),
		Baseline:    func(context.Context) ([]byte, uint64, error) { return nil, 0, store.ErrNotFound },
		BaselinePub: pub, Samples: objects, Binary: bin, Poll: 50 * time.Millisecond}
	if err := runner.Init(); err != nil {
		t.Fatal(err)
	}
	go func() { _ = runner.Run(ctx) }()

	is := authtest.New(t)
	v, err := auth.NewVerifier(ctx, auth.Config{Issuer: is.URL, Audience: authtest.Audience})
	if err != nil {
		t.Fatal(err)
	}
	adm, err := admin.New(ctx, v, admin.BuildInfo{Version: "e2e"}, admin.Deps{Policies: st, Operations: st, ReplayKick: runner.Kick, Deployer: deployer})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(adm.Close)
	e := &fleetEnv{issuer: is, rest: api.NewServer(api.ServerConfig{Auth: v, Admin: adm.Gateway}, ingest.NewMockEventStore()).Handler()}

	type example struct {
		RawURI     string   `json:"raw_uri"`
		DraftRules []uint32 `json:"draft_rules"`
	}
	type op struct {
		ID       string `json:"id"`
		State    string `json:"state"`
		Done     bool   `json:"done"`
		Error    string `json:"error"`
		PolicyID string `json:"policy_id"`
		Version  uint32 `json:"version"`
		Replay   *struct {
			InputDigest    string   `json:"input_digest"`
			DraftSHA256    string   `json:"draft_sha256"`
			BaselineSHA256 string   `json:"baseline_sha256"`
			ReplaySHA256   string   `json:"replay_sha256"`
			SampleSHA256   []string `json:"sample_sha256"`
			Samples        string   `json:"samples"`
			SampleFiles    uint32   `json:"sample_files"`
			Traffic        *struct {
				NewlyBlocked      string            `json:"newly_blocked"`
				NewlyBlockedRules map[string]string `json:"newly_blocked_rules"`
				ExamplesBlocked   []example         `json:"examples_blocked"`
			} `json:"traffic"`
			Corpus *struct{} `json:"corpus"`
		} `json:"replay"`
	}
	wait := func(id string) op {
		t.Helper()
		deadline := time.Now().Add(30 * time.Second)
		for {
			var out struct {
				Operation op `json:"operation"`
			}
			if c := e.call(t, "viewer", http.MethodGet, "/v1/operations/"+id, "", &out); c != http.StatusOK {
				t.Fatalf("GET operation: %d", c)
			}
			if out.Operation.Done {
				return out.Operation
			}
			if time.Now().After(deadline) {
				t.Fatalf("operation %s not done: %+v", id, out.Operation)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}

	var created struct {
		ReplayOperation string `json:"replay_operation"`
	}
	if c := e.call(t, "operator", http.MethodPost, "/v1/policies",
		`{"id":"example-api","name":"example-api","spec":{"mode":"MODE_SHADOW"}}`, &created); c != http.StatusOK || !strings.HasPrefix(created.ReplayOperation, "op-") {
		t.Fatalf("create: %d %+v", c, created)
	}
	got := wait(created.ReplayOperation)
	if got.State != "DONE" || got.PolicyID != "example-api" || got.Version != 1 || got.Replay == nil || got.Replay.Samples != "5" ||
		got.Replay.SampleFiles != 1 || got.Replay.Traffic == nil || got.Replay.Corpus != nil || got.Replay.Traffic.NewlyBlockedRules["942100"] != "2" {
		t.Fatalf("replay of the new policy: %+v (%s)", got, got.Error)
	}
	if len(got.Replay.InputDigest) != 64 || len(got.Replay.DraftSHA256) != 64 || len(got.Replay.BaselineSHA256) != 64 || len(got.Replay.ReplaySHA256) != 64 || len(got.Replay.SampleSHA256) != 1 {
		t.Fatalf("API lost provenance: %+v", got.Replay)
	}
	if len(got.Replay.Traffic.ExamplesBlocked) != 0 {
		t.Fatalf("a viewer sees examples: %+v", got.Replay.Traffic.ExamplesBlocked)
	}

	// the result by version; examples for those who may read input
	var byVersion struct {
		Operation op `json:"operation"`
	}
	if c := e.call(t, "approver", http.MethodGet, "/v1/policies/example-api/versions/1/replay", "", &byVersion); c != http.StatusOK ||
		byVersion.Operation.ID != created.ReplayOperation || len(byVersion.Operation.Replay.Traffic.ExamplesBlocked) != 1 ||
		byVersion.Operation.Replay.Traffic.ExamplesBlocked[0].DraftRules[0] != 942100 {
		t.Fatalf("by version: %d %+v", c, byVersion)
	}
	if c := e.call(t, "viewer", http.MethodGet, "/v1/policies/example-api/versions/2/replay", "", nil); c != http.StatusNotFound {
		t.Fatalf("no replay of version 2: %d", c)
	}

	// POST :replay: viewers may not; an operator queues another of the newest
	if c := e.call(t, "viewer", http.MethodPost, "/v1/policies/example-api:replay", `{}`, nil); c != http.StatusForbidden {
		t.Fatalf("viewer replays: %d", c)
	}
	if c := e.call(t, "operator", http.MethodPost, "/v1/policies/example-api:replay", `{"version":3}`, nil); c != http.StatusNotFound {
		t.Fatalf("replay of a missing version: %d", c)
	}
	var again struct {
		Operation op `json:"operation"`
	}
	if c := e.call(t, "operator", http.MethodPost, "/v1/policies/example-api:replay", `{}`, &again); c != http.StatusOK ||
		again.Operation.Version != 1 || again.Operation.ID == created.ReplayOperation {
		t.Fatalf("replay again: %d %+v", c, again)
	}
	if got := wait(again.Operation.ID); got.State != "DONE" {
		t.Fatalf("second replay: %+v", got)
	}
	// PO 16/10: approved once the replay is DONE (it is, above)
	approve(t, e.call, "example-api")
	approved, err := st.GetPolicyVersion(ctx, "example-api", 1)
	if err != nil || approved.ApprovedReplayID != again.Operation.ID {
		t.Fatalf("approval proof: %+v %v", approved, err)
	}
	if err := os.WriteFile(rules, []byte("changed rules"), 0600); err != nil {
		t.Fatal(err)
	}
	if c := e.call(t, "operator", http.MethodPost, "/v1/policies/example-api:deploy", `{}`, nil); c != http.StatusBadRequest {
		t.Fatalf("deploy after input change: %d", c)
	}
	// Replaying changed inputs after approval does not approve those inputs.
	if c := e.call(t, "operator", http.MethodPost, "/v1/policies/example-api:replay", `{}`, &again); c != http.StatusOK {
		t.Fatal("replay changed inputs", c)
	}
	if got := wait(again.Operation.ID); got.State != "DONE" {
		t.Fatalf("changed replay: %+v", got)
	}
	if c := e.call(t, "operator", http.MethodPost, "/v1/policies/example-api:deploy", `{}`, nil); c != http.StatusBadRequest {
		t.Fatalf("unapproved new replay deployed: %d", c)
	}
	if _, err := st.LatestBundle(ctx); err != store.ErrNotFound {
		t.Fatalf("rejected deploy persisted bundle: %v", err)
	}
	if err := os.WriteFile(rules, []byte("original rules"), 0600); err != nil {
		t.Fatal(err)
	}
	if c := e.call(t, "operator", http.MethodPost, "/v1/policies/example-api:deploy", `{}`, nil); c != http.StatusOK {
		t.Fatalf("deploy approved inputs: %d", c)
	}
	b, err := st.LatestBundle(ctx)
	if err != nil || len(b.InputDigest) != 64 {
		t.Fatalf("published provenance: %+v %v", b, err)
	}

	if c := e.call(t, "viewer", http.MethodGet, "/v1/operations/op-000000000000000000000000", "", nil); c != http.StatusNotFound {
		t.Fatalf("missing operation: %d", c)
	}
}
