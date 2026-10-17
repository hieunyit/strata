package policy_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/strata/strata/agent/pkg/bundlefmt"
	"github.com/strata/strata/control-plane/localauth/localauthtest"
	"github.com/strata/strata/control-plane/policy"
	"github.com/strata/strata/control-plane/replay"
	"github.com/strata/strata/control-plane/store"
)

type stagingObjects map[string][]byte

func (o stagingObjects) Put(_ context.Context, key string, b []byte, _ string) error {
	o[key] = bytes.Clone(b)
	return nil
}
func (o stagingObjects) Get(_ context.Context, key string) ([]byte, error) {
	b, ok := o[key]
	if !ok {
		return nil, store.ErrNotFound
	}
	return bytes.Clone(b), nil
}

type writerFixture struct {
	pool    *pgxpool.Pool
	store   *store.Store
	writer  *policy.StagingDeployer
	objects stagingObjects
	source  store.Bundle
	rules   string
	calls   int
}

func newStagingWriter(t *testing.T, enabled bool) *writerFixture {
	t.Helper()
	bin := os.Getenv("STRATA_TEST_COMPILER")
	if bin == "" {
		t.Skip("STRATA_TEST_COMPILER not set")
	}
	pool := localauthtest.Pool(t)
	s := store.New(pool)
	ctx := t.Context()
	author := store.Audit{Actor: "operator", Subject: "operator"}
	raw := `{"mode":"enforce","auto_staging":{"enabled":true,"rule_ids":[700011],"window_seconds":300,"min_matches":100,"min_reports":5,"fp_threshold_bps":500}}`
	if !enabled {
		raw = strings.Replace(raw, `"enabled":true`, `"enabled":false`, 1)
	}
	p, err := s.CreatePolicy(ctx, store.Policy{ID: "example-api", Name: "example-api", Spec: []byte(raw)}, author)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	key := filepath.Join(dir, "example.key")
	rules := filepath.Join(dir, "rules.yaml")
	seed := bytes.Repeat([]byte{7}, 32)
	if err = os.WriteFile(key, seed, 0600); err != nil {
		t.Fatal(err)
	}
	ir := `ir_version: 1
ruleset: {name: example, version: '1'}
rules:
 - id: 700011
   name: example SQLi
   layer: managed
   stage: request_headers
   score: 100
   severity: critical
   match:
     all:
      - targets: [{var: args}]
        operator: {type: detect_sqli}
   metadata: {source: organization, license: Apache-2.0}
`
	if err = os.WriteFile(rules, []byte(ir), 0600); err != nil {
		t.Fatal(err)
	}
	spec, err := policy.Parse(p.Spec)
	if err != nil {
		t.Fatal(err)
	}
	compiler := &policy.Compiler{Binary: bin, KeyFile: key, Rules: []string{rules}, StagingStore: s}
	prepared, err := compiler.Prepare(ctx, []policy.Named{{ResourceID: p.ID, Version: 1, Name: p.Name, Spec: spec}})
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Close()
	blob, err := prepared.Build(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(blob)
	source := store.Bundle{Version: 1, InputDigest: prepared.Digest, SHA256: sum[:], ObjectKey: policy.ObjectKey(1), SizeBytes: int64(len(blob)), Contents: map[string]int{p.ID: 1}}
	if _, err = s.SubmitPolicyVersion(ctx, p.ID, 1, author); err != nil {
		t.Fatal(err)
	}
	// Proof fixture exercises approval binding/gates; this test does not invoke
	// a replay executable or claim replay-corpus quality.
	op, err := s.CreateReplayOperation(ctx, p.ID, 1, author)
	if err != nil {
		t.Fatal(err)
	}
	if _, claimed, err := s.ClaimOperation(ctx, time.Now().Add(-time.Hour)); err != nil || !claimed {
		t.Fatalf("claim: %v %v", claimed, err)
	}
	proof, err := json.Marshal(replay.Report{InputDigest: source.InputDigest, DraftSHA256: hex.EncodeToString(sum[:]), BaselineSHA256: strings.Repeat("b", 64), Corpus: &replay.Route{Samples: 100}})
	if err != nil {
		t.Fatal(err)
	}
	if err = s.FinishOperation(ctx, op.ID, proof, ""); err != nil {
		t.Fatal(err)
	}
	if _, err = s.DecidePolicyVersion(ctx, p.ID, 1, true, "", store.Audit{Actor: "approver", Subject: "approver", ReplayOperation: op.ID}); err != nil {
		t.Fatal(err)
	}
	if source, err = s.RecordBundle(ctx, source, author); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO connector_groups(id,name) VALUES('example-edge','example-edge'); INSERT INTO nodes(id,group_id) VALUES('example-node','example-edge')`); err != nil {
		t.Fatal(err)
	}
	ro, _, err := s.CreateRollout(ctx, 1, []string{"example-node"}, []float64{1}, 0, author)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.ReportBundleStatus(ctx, "example-node", 1, "ACTIVE", ""); err != nil {
		t.Fatal(err)
	}
	if _, err = s.AdvanceRollout(ctx, ro.ID); err != nil {
		t.Fatal(err)
	}
	objects := stagingObjects{source.ObjectKey: blob}
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	f := &writerFixture{pool: pool, store: s, objects: objects, source: source, rules: rules}
	f.writer = &policy.StagingDeployer{Store: s, Compiler: compiler, Objects: objects, PubKey: pub, VerifySource: (replay.Gate{Store: s}).CheckStaging, Now: func() time.Time { return time.Date(2026, 10, 17, 2, 0, 0, 0, time.UTC) }}
	f.writer.Observe = func(_ context.Context, _ policy.Spec, rule uint32, name string, bundle uint64, now time.Time) (policy.StagingEvidence, error) {
		f.calls++
		return policy.StagingEvidence{RuleID: rule, PolicyName: name, BundleVersion: bundle, From: now.Add(-5 * time.Minute), To: now, Matches: 100, Reports: 5}, nil
	}
	return f
}

func TestAuthorizedStagingWriterRealCompilerAndPostgres(t *testing.T) {
	f := newStagingWriter(t, true)
	ctx := t.Context()
	action, err := f.writer.Stage(ctx, 1, "example-api", 1, 700011)
	if err != nil {
		t.Fatal(err)
	}
	if action.BundleVersion != 2 || action.SourceBundle != 1 || action.RolloutID != nil || f.calls != 1 {
		t.Fatalf("action: %+v queries=%d", action, f.calls)
	}
	latest, err := f.store.LatestBundle(ctx)
	if err != nil || latest.InputDigest == f.source.InputDigest {
		t.Fatalf("derived digest: %+v %v", latest, err)
	}
	blob := f.objects[latest.ObjectKey]
	header, err := bundlefmt.Verify(blob, f.writer.PubKey)
	if err != nil || header.Version != 2 || blob[64+62]&32 == 0 {
		t.Fatalf("signed overlay: %+v %v", header, err)
	}
	state, err := store.New(f.pool).StagedRules(ctx, f.source.Contents)
	if err != nil || len(state["example-api"]) != 1 || state["example-api"][0] != 700011 {
		t.Fatalf("lost ledger: %v %v", state, err)
	}
	if _, err = f.writer.Stage(ctx, 1, "example-api", 1, 700011); !errors.Is(err, store.ErrStagingConflict) {
		t.Fatalf("stale retry: %v", err)
	}
	if _, err = f.writer.Stage(ctx, 2, "example-api", 1, 700011); !errors.Is(err, policy.ErrStagingNotEligible) {
		t.Fatalf("recorded != active: %v", err)
	}
	var count int
	if err = f.pool.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action='rule-staging:record'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("audit: %d %v", count, err)
	}
}

func TestStagingWriterRejectsUnsafeOrUnboundInputs(t *testing.T) {
	for _, name := range []string{"disabled", "fraction below threshold", "overflow fraction below threshold", "wrong evidence bundle", "changed compiler inputs", "invalid source signature", "source not active", "query error", "missing verifier"} {
		t.Run(name, func(t *testing.T) {
			f := newStagingWriter(t, name != "disabled")
			ctx := t.Context()
			original := f.writer.Observe
			switch name {
			case "fraction below threshold":
				f.writer.Observe = func(c context.Context, s policy.Spec, r uint32, n string, b uint64, now time.Time) (policy.StagingEvidence, error) {
					e, err := original(c, s, r, n, b, now)
					e.Matches = 101
					return e, err
				}
			case "overflow fraction below threshold":
				f.writer.Observe = func(c context.Context, s policy.Spec, r uint32, n string, b uint64, now time.Time) (policy.StagingEvidence, error) {
					e, err := original(c, s, r, n, b, now)
					e.Matches = math.MaxUint64
					e.Reports = math.MaxUint64 / 20
					return e, err
				}
			case "wrong evidence bundle":
				f.writer.Observe = func(c context.Context, s policy.Spec, r uint32, n string, b uint64, now time.Time) (policy.StagingEvidence, error) {
					e, err := original(c, s, r, n, b, now)
					e.BundleVersion++
					return e, err
				}
			case "changed compiler inputs":
				file, err := os.OpenFile(f.rules, os.O_APPEND|os.O_WRONLY, 0600)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = file.WriteString("\n# changed after approval\n"); err != nil {
					t.Fatal(err)
				}
				if err = file.Close(); err != nil {
					t.Fatal(err)
				}
			case "invalid source signature":
				f.objects[f.source.ObjectKey][len(f.objects[f.source.ObjectKey])-1] ^= 1
			case "source not active":
				if _, err := f.pool.Exec(ctx, `UPDATE nodes SET bundle_state='VERIFIED'`); err != nil {
					t.Fatal(err)
				}
			case "query error":
				f.writer.Observe = func(context.Context, policy.Spec, uint32, string, uint64, time.Time) (policy.StagingEvidence, error) {
					return policy.StagingEvidence{}, errors.New("database unavailable")
				}
			case "missing verifier":
				f.writer.VerifySource = nil
			}
			if _, err := f.writer.Stage(ctx, 1, "example-api", 1, 700011); err == nil {
				t.Fatal("unsafe derivation recorded")
			}
			wantCalls := 0
			if name == "fraction below threshold" || name == "overflow fraction below threshold" || name == "wrong evidence bundle" {
				wantCalls = 1
			}
			if f.calls != wantCalls {
				t.Fatalf("guard ordering: observations=%d want=%d", f.calls, wantCalls)
			}
			latest, err := f.store.LatestBundle(ctx)
			if err != nil || latest.Version != 1 || len(f.objects) != 1 {
				t.Fatalf("failed attempt published: %+v objects=%d err=%v", latest, len(f.objects), err)
			}
		})
	}
}
