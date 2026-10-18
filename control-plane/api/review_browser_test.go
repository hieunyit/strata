package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/strata/strata/control-plane/admin"
	"github.com/strata/strata/control-plane/auth"
	"github.com/strata/strata/control-plane/ingest"
	"github.com/strata/strata/control-plane/localauth"
	"github.com/strata/strata/control-plane/localauth/localauthtest"
	"github.com/strata/strata/control-plane/policy"
	"github.com/strata/strata/control-plane/replay"
	"github.com/strata/strata/control-plane/store"
)

func TestPolicyReviewBrowserLab(t *testing.T) {
	host, network, build, output := os.Getenv("STRATA_BROWSER_HOST_REPO"), os.Getenv("STRATA_BROWSER_NETWORK"), os.Getenv("STRATA_BROWSER_UI_BUILD"), os.Getenv("STRATA_REVIEW_EVIDENCE_DIR")
	compiler, replayBin := os.Getenv("STRATA_TEST_COMPILER"), os.Getenv("STRATA_TEST_REPLAY_BIN")
	if host == "" || network == "" || build == "" || output == "" || compiler == "" || replayBin == "" {
		t.Skip("isolated review browser and real compiler/replay paths required")
	}
	if err := os.Mkdir(output, 0755); err != nil {
		t.Fatal("new output directory required", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	pool := localauthtest.Pool(t)
	pg := store.New(pool)
	accounts := localauth.NewStore(pool)
	sessions, err := localauth.NewService(accounts, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	var secret [24]byte
	if _, err = rand.Read(secret[:]); err != nil {
		t.Fatal(err)
	}
	password := hex.EncodeToString(secret[:])
	for name, roles := range map[string][]string{"writer": {"operator", "approver"}, "reviewer": {"approver"}, "viewer": {"viewer"}} {
		hash, e := localauth.HashPassword(password)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = accounts.CreateUser(ctx, "example-"+name, hash, roles, "system:lab"); e != nil {
			t.Fatal(e)
		}
	}
	author := store.Audit{Actor: "example-writer", Subject: localauth.SubjectPrefix + "example-writer"}
	first, err := pg.CreatePolicy(ctx, store.Policy{ID: "resource-api", Name: "example-api", Spec: []byte(`{"mode":"shadow"}`)}, author)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	rulesFile, corpus := filepath.Join(dir, "rules.yaml"), filepath.Join(dir, "corpus.parquet")
	if err = os.WriteFile(rulesFile, []byte(workflowRule), 0600); err != nil {
		t.Fatal(err)
	}
	var data bytes.Buffer
	records := []replay.Record{}
	for i, args := range []string{"q=1+OR+1%3D1", "q=example"} {
		action := "allow"
		if i == 0 {
			action = "block"
		}
		records = append(records, replay.Record{TsMs: time.Now().UnixMilli(), NodeID: "example-node", Policy: first.Name, Method: "GET", URI: "/search", RawURI: "/search?" + args, Args: args, Proto: "HTTP/1.1", Headers: `[["Host","api.example.test"]]`, Action: action})
	}
	if err = replay.WriteParquet(&data, "synthetic", records); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(corpus, data.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	c := policy.Compiler{Binary: compiler, Rules: []string{rulesFile}}
	runner := &replay.Runner{Store: pg, Prepare: c.Prepare, Build: replay.ReplayBuilder(c), Deployable: pg.DeployablePolicies, Baseline: func(context.Context) ([]byte, uint64, error) { return nil, 0, store.ErrNotFound }, Corpus: corpus, Binary: replayBin, Timeout: 30 * time.Second, Poll: time.Second}
	if err = runner.Init(); err != nil {
		t.Fatal(err)
	}
	if _, err = pg.CreateReplayOperation(ctx, first.ID, 1, author); err != nil {
		t.Fatal(err)
	}
	if !runner.RunOnce(ctx) {
		t.Fatal("seed replay not claimed")
	}
	seed, err := pg.LatestReplay(ctx, first.ID, 1)
	if err != nil || seed.State != store.OpDone {
		t.Fatal("seed replay", seed.State, err)
	}
	if _, err = pg.SubmitPolicyVersion(ctx, first.ID, 1, author); err != nil {
		t.Fatal(err)
	}
	if _, err = pg.DecidePolicyVersion(ctx, first.ID, 1, true, "initial baseline", store.Audit{Actor: "seed-reviewer", Subject: "seed-reviewer", ReplayOperation: seed.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err = pg.UpdatePolicy(ctx, first.ID, first.Etag, []byte(`{"mode":"enforce"}`), author); err != nil {
		t.Fatal(err)
	}
	workerCtx, stopWorker := context.WithCancel(ctx)
	workerDone := make(chan error, 1)
	go func() { workerDone <- runner.Run(workerCtx) }()
	defer func() {
		stopWorker()
		if e := <-workerDone; e != nil {
			t.Error(e)
		}
	}()
	dispatch := auth.Dispatch{Local: sessions, LocalPrefix: localauth.TokenPrefix}
	adm, err := admin.New(ctx, dispatch, admin.BuildInfo{Version: "example-review"}, admin.Deps{Policies: pg, Operations: pg, ReplayKick: runner.Kick})
	if err != nil {
		t.Fatal(err)
	}
	defer adm.Close()
	server := NewServer(ServerConfig{Auth: dispatch, Admin: adm.Gateway, StagingNotices: pg, Local: &localauth.Handler{Service: sessions, Store: accounts}}, ingest.NewMockEventStore())
	apiHandler := server.Handler()
	var injected atomic.Bool
	replacement := make(chan string, 1)
	// Real race injection: another replay completes after the browser sends
	// its pinned approval but before the real gateway/store processes it.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/v1/policies/resource-api:approve" {
			principal, e := dispatch.Authenticate(r.Context(), auth.BearerToken(r.Header.Get("Authorization")))
			if e == nil && principal.Name == "example-reviewer" && injected.CompareAndSwap(false, true) {
				op, e := pg.CreateReplayOperation(r.Context(), first.ID, 2, store.Audit{Actor: "system:race-fixture", Subject: "system:race-fixture"})
				if e != nil {
					http.Error(w, "fixture queue failed", 500)
					return
				}
				runner.Kick()
				for {
					latest, e := pg.GetOperation(r.Context(), op.ID)
					if e != nil || latest.State == store.OpFailed {
						http.Error(w, "fixture replay failed", 500)
						return
					}
					if latest.State == store.OpDone {
						replacement <- op.ID
						break
					}
					select {
					case <-r.Context().Done():
						return
					case <-time.After(10 * time.Millisecond):
					}
				}
			}
		}
		apiHandler.ServeHTTP(w, r)
	})
	mux := http.NewServeMux()
	mux.Handle("/v1/", handler)
	mux.Handle("/", http.FileServer(http.Dir(build)))
	httpServer := httptest.NewServer(mux)
	defer httpServer.Close()
	browserName := "strata-review-browser-" + pool.Config().ConnConfig.Database
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		out, e := exec.CommandContext(cleanupCtx, "docker", "inspect", "--type", "container", "--format", "{{.Name}}", browserName).CombinedOutput()
		if e != nil {
			if strings.Contains(string(out), "No such object") || strings.Contains(string(out), "No such container") {
				return
			}
			t.Errorf("inspect owned browser cleanup: %v %s", e, out)
			return
		}
		if out, e = exec.CommandContext(cleanupCtx, "docker", "rm", "-f", browserName).CombinedOutput(); e != nil {
			t.Errorf("owned browser cleanup: %v %s", e, out)
		}
	})
	cmd := exec.CommandContext(ctx, "docker", "run", "--rm", "--name", browserName, "--network", network, "--cpuset-cpus=11-12", "-u", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()), "-v", host+":/src", "-w", "/src/ui", "-e", "STRATA_REVIEW_LAB_URL", "-e", "STRATA_REVIEW_LAB_PASSWORD", "-e", "STRATA_REVIEW_EVIDENCE_DIR", "mcr.microsoft.com/playwright:v1.64.0-noble", "npx", "--no-install", "playwright", "test", "-c", "playwright.reviews.config.ts", "--output", filepath.Join(output, "results"))
	cmd.Env = append(os.Environ(), "STRATA_REVIEW_LAB_URL="+httpServer.URL, "STRATA_REVIEW_LAB_PASSWORD="+password, "STRATA_REVIEW_EVIDENCE_DIR="+output)
	raw, err := cmd.CombinedOutput()
	t.Logf("%s", raw)
	if err != nil {
		t.Fatal("review browser", err)
	}
	var proof string
	select {
	case proof = <-replacement:
	default:
		t.Fatal("race was not exercised")
	}
	saved, err := pg.GetPolicyVersion(ctx, first.ID, 2)
	if err != nil || saved.State != store.VersionApproved || saved.ApprovedReplayID != proof || saved.DecidedBy != "example-reviewer (local:example-reviewer)" {
		t.Fatal("decision proof", saved, err)
	}
	var decidedSubject string
	if err = pool.QueryRow(ctx, `SELECT decided_subject FROM policy_versions WHERE policy_id=$1 AND version=2`, first.ID).Scan(&decidedSubject); err != nil || decidedSubject != localauth.SubjectPrefix+"example-reviewer" {
		t.Fatal("canonical decision subject", decidedSubject, err)
	}
	audits, err := pg.AuditEntries(ctx, 200)
	if err != nil {
		t.Fatal(err)
	}
	decisions := map[string]int{}
	for _, a := range audits {
		if a.Resource == "policies/resource-api/versions/2:approve" || a.Resource == "policies/resource-api/versions/2:reject" {
			decisions[a.Resource]++
		}
	}
	if decisions["policies/resource-api/versions/2:approve"] != 1 || decisions["policies/resource-api/versions/2:reject"] != 1 {
		t.Fatal("unexpected audited decisions", decisions)
	}
	if _, err = pg.LatestBundle(ctx); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("browser unexpectedly deployed a bundle", err)
	}
	latest, err := pg.LatestReplay(ctx, first.ID, 2)
	if err != nil || latest.ID == proof || latest.State != store.OpDone {
		t.Fatal("later replay not exercised", latest.ID, err)
	}
	var later replay.Report
	if err = json.Unmarshal(latest.Result, &later); err != nil || later.Corpus == nil || later.Corpus.NewlyBlocked != 0 {
		t.Fatal("later baseline did not use approved policy", later.Corpus, err)
	}
	op, err := pg.GetOperation(ctx, proof)
	if err != nil {
		t.Fatal(err)
	}
	var report replay.Report
	if err = json.Unmarshal(op.Result, &report); err != nil || report.Samples() != 2 || report.Corpus == nil || report.Corpus.NewlyBlocked != 1 || report.Corpus.NewlyAllowed != 0 || report.Corpus.NewlyBlockedSampled["block"] != 1 {
		t.Fatal("real verdict comparison", report.Corpus, err)
	}
	if err = os.WriteFile(filepath.Join(output, "approved-replay.json"), op.Result, 0644); err != nil {
		t.Fatal(err)
	}
	summary, err := json.MarshalIndent(map[string]any{"state": saved.State, "approved_replay_id": proof, "decided_by": saved.DecidedBy, "decisions": decisions, "no_deployed_bundle": true, "latest_replay_id": latest.ID, "latest_replay_does_not_replace_approval": latest.ID != proof}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(output, "persisted-result.json"), summary, 0644); err != nil {
		t.Fatal(err)
	}
	t.Log("PASS: real replay worker, writer self-approval refused, reject/resubmit, stale pin refused, independent approval persisted exact replacement; no deployment")
}
