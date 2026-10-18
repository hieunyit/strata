package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/strata/strata/control-plane/admin"
	"github.com/strata/strata/control-plane/ingest"
	"github.com/strata/strata/control-plane/localauth/localauthtest"
	"github.com/strata/strata/control-plane/policy"
	"github.com/strata/strata/control-plane/replay"
	"github.com/strata/strata/control-plane/rulecat"
	"github.com/strata/strata/control-plane/store"
)

// This boundary holds published objects only. Compiler, replay, PostgreSQL,
// authorization and policy state transitions below are their real implementations.
type workflowObjects map[string][]byte

func (o workflowObjects) Put(_ context.Context, key string, data []byte, sum string) error {
	h := sha256.Sum256(data)
	if hex.EncodeToString(h[:]) != sum {
		return fmt.Errorf("object digest mismatch")
	}
	o[key] = bytes.Clone(data)
	return nil
}
func (o workflowObjects) Get(_ context.Context, key string) ([]byte, error) {
	b, ok := o[key]
	if !ok {
		return nil, store.ErrNotFound
	}
	return bytes.Clone(b), nil
}

const workflowRule = `ir_version: 1
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
        - targets: [{var: args}, {var: request_headers}]
          operator: {type: detect_sqli}
    metadata: {source: organization, license: Apache-2.0}
`

func TestExceptionRealWorkflowInPostgres(t *testing.T) {
	compilerBin, replayBin, evalBin := os.Getenv("STRATA_TEST_COMPILER"), os.Getenv("STRATA_TEST_REPLAY_BIN"), os.Getenv("STRATA_TEST_EVAL_BIN")
	if compilerBin == "" || replayBin == "" || evalBin == "" {
		t.Skip("real compiler/replay/eval paths required")
	}
	ctx := t.Context()
	pg := store.New(localauthtest.Pool(t))
	dir := t.TempDir()
	evidence := os.Getenv("STRATA_EXCEPTION_WORKFLOW_DIR")
	if evidence == "" {
		evidence = filepath.Join(dir, "evidence")
	}
	if err := os.MkdirAll(evidence, 0700); err != nil {
		t.Fatal(err)
	}
	seed := bytes.Repeat([]byte{7}, 32)
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	keyFile, rulesFile, corpus := filepath.Join(dir, "deploy.seed"), filepath.Join(dir, "rules.yaml"), filepath.Join(dir, "corpus.parquet")
	write := func(path string, data []byte) {
		t.Helper()
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(keyFile, seed)
	write(rulesFile, []byte(workflowRule))
	var samples bytes.Buffer
	records := []replay.Record{}
	for i, args := range []string{"", "other=1+OR+1%3D1", ""} {
		value := "1 OR 1=1"
		if i == 2 {
			value = "1"
		}
		uri := "/header-sql"
		if args != "" {
			uri += "?" + args
		}
		headers, _ := json.Marshal([][2]string{{"Host", "api.example.test"}, {"X-Example-Filter", value}})
		records = append(records, replay.Record{TsMs: time.Now().UnixMilli(), NodeID: "example-node", Policy: "example-api", Method: "GET", URI: "/header-sql", RawURI: uri, Args: args, Proto: "HTTP/1.1", Client: "192.0.2.10", Headers: string(headers), Rules: "[]", Action: "block"})
	}
	if err := replay.WriteParquet(&samples, "synthetic", records); err != nil {
		t.Fatal(err)
	}
	write(corpus, samples.Bytes())
	first, err := pg.CreatePolicy(ctx, store.Policy{ID: "resource-api", Name: "example-api", Spec: json.RawMessage(`{"mode":"enforce"}`)}, store.Audit{Actor: "creator", Subject: "creator-sub", Action: "policies.create"})
	if err != nil {
		t.Fatal(err)
	}
	c := &policy.Compiler{Binary: compilerBin, KeyFile: keyFile, Rules: []string{rulesFile}, CostBudget: policy.DefaultCostBudget}
	low := *c
	low.CostBudget = 1
	if _, err := low.Build(ctx, 1, []policy.Named{{Name: first.Name, Spec: policy.Spec{Mode: "enforce"}}}); err == nil {
		t.Fatal("real compiler allowed over-budget policy")
	} else {
		var costErr *policy.CostError
		if !errors.As(err, &costErr) {
			t.Fatal("not a cost rejection", err)
		}
	}
	objects := workflowObjects{}
	baseline := func(ctx context.Context) ([]byte, uint64, error) {
		b, err := pg.LatestBundle(ctx)
		if err != nil {
			return nil, 0, err
		}
		raw, err := objects.Get(ctx, b.ObjectKey)
		return raw, b.Version, err
	}
	runner := &replay.Runner{Store: pg, Prepare: c.Prepare, Build: replay.ReplayBuilder(*c), Deployable: pg.DeployablePolicies, Baseline: baseline, BaselinePub: pub, Corpus: corpus, Binary: replayBin, Timeout: time.Minute}
	if err := runner.Init(); err != nil {
		t.Fatal(err)
	}
	deployer := &policy.Deployer{Store: pg, Builder: c, Objects: objects, PubKey: pub, VerifyReplay: (replay.Gate{Store: pg}).Check}
	adm, err := admin.New(ctx, tokenRoles{}, admin.BuildInfo{}, admin.Deps{Policies: pg, Operations: pg, ReplayKick: runner.Kick, Deployer: deployer})
	if err != nil {
		t.Fatal(err)
	}
	defer adm.Close()
	catalog, err := rulecat.Load([]string{rulesFile})
	if err != nil {
		t.Fatal(err)
	}
	events := ingest.NewMockEventStore()
	if err := events.SaveEvents(ctx, []ingest.Event{{BlockID: exceptionBlock, Timestamp: time.Now(), PolicyID: first.Name, HTTPMethod: "GET", HTTPHost: "api.example.test", HTTPPath: "/header-sql", Action: "block", Violations: []ingest.Violation{{RuleID: 700011, Field: "REQUEST_HEADERS:X-Example-Filter"}}}}); err != nil {
		t.Fatal(err)
	}
	s := NewServer(ServerConfig{Auth: tokenRoles{}, Exceptions: pg, ReplayKick: runner.Kick, Rules: catalog, Admin: adm.Gateway, DeployTimeout: time.Minute}, events)
	post := func(role, path string, body any, want int) map[string]any {
		t.Helper()
		code, reply := do(t, s, "POST", path, role, body)
		if code != want {
			t.Fatalf("%s %s: code=%d want=%d reply=%v", role, path, code, want, reply)
		}
		return reply
	}
	runReplay := func(version int) replay.Report {
		t.Helper()
		if !runner.RunOnce(ctx) {
			t.Fatal("nothing queued")
		}
		op, err := pg.LatestReplay(ctx, first.ID, version)
		if err != nil || op.State != store.OpDone {
			t.Fatalf("real replay: %+v %v", op, err)
		}
		var rep replay.Report
		if err := json.Unmarshal(op.Result, &rep); err != nil {
			t.Fatal(err)
		}
		if rep.Samples() != 3 || len(rep.InputDigest) != 64 {
			t.Fatalf("invalid report %+v", rep)
		}
		raw, err := json.MarshalIndent(rep, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		write(filepath.Join(evidence, fmt.Sprintf("replay-v%d.json", version)), raw)
		return rep
	}
	approveDeploy := func(version int) store.Bundle {
		t.Helper()
		post("operator", "/v1/policies/resource-api:submit", map[string]int{"version": version}, 200)
		post("operator", "/v1/policies/resource-api:approve", map[string]int{"version": version}, 403)
		post("approver", "/v1/policies/resource-api:approve", map[string]int{"version": version}, 200)
		post("operator", "/v1/policies/resource-api:deploy", map[string]any{}, 200)
		b, err := pg.LatestBundle(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	if _, err := pg.CreateReplayOperation(ctx, first.ID, 1, store.Audit{Actor: "creator", Action: "policies.replay"}); err != nil {
		t.Fatal(err)
	}
	runReplay(1)
	b1 := approveDeploy(1)
	inspect := func(label string, b store.Bundle, want string) {
		t.Helper()
		artifact := filepath.Join(evidence, label)
		if err := os.MkdirAll(artifact, 0700); err != nil {
			t.Fatal(err)
		}
		raw, err := objects.Get(ctx, b.ObjectKey)
		if err != nil {
			t.Fatal(err)
		}
		write(filepath.Join(artifact, "bundle.sbn"), raw)
		write(filepath.Join(artifact, "bundle.pub"), pub)
		input := `{"uri":"/header-sql","headers":{"Host":"api.example.test","X-Example-Filter":"1 OR 1=1"}}` + "\n" + `{"uri":"/header-sql?other=1+OR+1%3D1","headers":{"Host":"api.example.test","X-Example-Filter":"1 OR 1=1"}}` + "\n"
		cmd := exec.CommandContext(ctx, evalBin, "--bundle", filepath.Join(artifact, "bundle.sbn"), "--pubkey", filepath.Join(artifact, "bundle.pub"), "--policy", "example-api")
		cmd.Stdin = strings.NewReader(input)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("eval %s: %s %v", label, out, err)
		}
		write(filepath.Join(artifact, "verdicts.jsonl"), out)
		rows := bytes.Split(bytes.TrimSpace(out), []byte("\n"))
		if len(rows) != 2 {
			t.Fatal("missing eval verdicts")
		}
		for i, row := range rows {
			var v struct {
				Action string
				Error  int
			}
			if err := json.Unmarshal(row, &v); err != nil {
				t.Fatal(err)
			}
			expected := "block"
			if i == 0 {
				expected = want
			}
			if v.Action != expected || v.Error != 0 {
				t.Fatalf("%s request %d: %s", label, i, row)
			}
		}
		if os.Getenv("STRATA_TEST_EXCEPTION_HTTP") == "1" {
			repo, err := filepath.Abs("../..")
			if err != nil {
				t.Fatal(err)
			}
			expected := "enforced"
			if want == "allow" {
				expected = "exempt"
			}
			cmd := exec.CommandContext(ctx, "python3", "tests/security/exception_probe.py", "--fixture-dir", artifact, "--out-dir", filepath.Join(artifact, "http"), "--expected", expected)
			cmd.Dir = repo
			out, err := cmd.CombinedOutput()
			write(filepath.Join(artifact, "http-check.txt"), out)
			if err != nil {
				t.Fatalf("HTTP %s: %s %v", label, out, err)
			}
			t.Logf("%s HTTP: %s", label, out)
		}
	}
	inspect("before", b1, "block")
	current, err := pg.GetPolicy(ctx, first.ID)
	if err != nil {
		t.Fatal(err)
	}
	req := exceptionRequest(current.Etag)
	req.Field = "REQUEST_HEADERS:X-Example-Filter"
	req.TTLSeconds = 60
	reply := post("operator", "/v1/exceptions:fromBlockId", req, 200)
	post("operator", "/v1/policies/resource-api:deploy", map[string]any{}, 400)
	// Approval is not possible before a completed replay, even for another subject.
	post("operator", "/v1/policies/resource-api:submit", map[string]int{"version": 2}, 200)
	post("approver", "/v1/policies/resource-api:approve", map[string]int{"version": 2}, 400)
	rep := runReplay(2)
	if rep.Corpus == nil || rep.Corpus.NewlyAllowed != 1 || rep.Corpus.NewlyBlocked != 0 {
		t.Fatalf("exception replay %+v", rep.Corpus)
	}
	post("operator", "/v1/policies/resource-api:approve", map[string]int{"version": 2}, 403)
	post("approver", "/v1/policies/resource-api:approve", map[string]int{"version": 2}, 200)
	// An override-layer replacement after approval invalidates the bound proof.
	write(rulesFile, []byte(strings.ReplaceAll(workflowRule, "layer: managed", "layer: override")))
	post("operator", "/v1/policies/resource-api:deploy", map[string]any{}, 400)
	write(rulesFile, []byte(workflowRule))
	post("operator", "/v1/policies/resource-api:deploy", map[string]any{}, 200)
	b2, err := pg.LatestBundle(ctx)
	if err != nil {
		t.Fatal(err)
	}
	inspect("approved", b2, "allow")
	expiry := int64(reply["exception"].(map[string]any)["expires_unix_ms"].(float64))
	// Revoke using the existing policy version workflow, not an independent RAM flag.
	current, err = pg.GetPolicy(ctx, first.ID)
	if err != nil {
		t.Fatal(err)
	}
	code, body := do(t, s, "PATCH", "/v1/policies/resource-api", "operator", map[string]any{"id": first.ID, "etag": current.Etag, "spec": map[string]any{"mode": "MODE_ENFORCE", "exceptions": []any{}}})
	if code != 200 {
		t.Fatalf("revoke draft %d %v", code, body)
	}
	post("operator", "/v1/policies/resource-api:deploy", map[string]any{}, 400)
	inspect("revoke-pending", b2, "allow")
	rep = runReplay(3)
	if rep.Corpus == nil || rep.Corpus.NewlyBlocked != 1 {
		t.Fatalf("revoke replay %+v", rep.Corpus)
	}
	b3 := approveDeploy(3)
	inspect("revoked", b3, "block")
	wait := time.Until(time.UnixMilli(expiry).Add(20 * time.Millisecond))
	if wait > 0 {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	inspect("expired-old-artifact", b2, "block")
	t.Logf("PASS: three signed policy deployments, 3 real replays, exact field exception, revoke and absolute TTL; evidence %s", evidence)
}
