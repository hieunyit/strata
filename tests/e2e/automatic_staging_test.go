package e2e

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/strata/strata/agent/pkg/bundlefmt"
	"github.com/strata/strata/control-plane/admin"
	"github.com/strata/strata/control-plane/api"
	"github.com/strata/strata/control-plane/auth"
	"github.com/strata/strata/control-plane/auth/authtest"
	"github.com/strata/strata/control-plane/db"
	"github.com/strata/strata/control-plane/fleet"
	"github.com/strata/strata/control-plane/ingest"
	"github.com/strata/strata/control-plane/policy"
	"github.com/strata/strata/control-plane/replay"
	"github.com/strata/strata/control-plane/rulehealth"
	"github.com/strata/strata/control-plane/store"
	"google.golang.org/grpc"
)

type automaticPlatform struct {
	*platform
	events   *ingest.ClickHouseStore
	runner   *replay.Runner
	compiler *policy.Compiler
	objects  *policy.S3
	rollouts *fleet.Rollouts
}

func startAutomaticPlatform(t *testing.T, compilerBin, replayBin string) *automaticPlatform {
	t.Helper()
	ctx := t.Context()
	pool := startPostgres(t)
	latest, err := db.Latest()
	if err != nil {
		t.Fatal(err)
	}
	if err = db.Migrate(ctx, pool, latest); err != nil {
		t.Fatal(err)
	}
	st := store.New(pool)
	events, _ := losslessClickHouse(t)
	schema, err := os.ReadFile(filepath.Join("..", "..", "control-plane", "ingest", "schema.sql"))
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range strings.Split(string(schema), ";") {
		if strings.TrimSpace(statement) != "" {
			if err = events.Conn().Exec(ctx, statement); err != nil {
				t.Fatalf("private events schema: %v", err)
			}
		}
	}
	if err = events.EnsureColumns(ctx); err != nil {
		t.Fatal(err)
	}
	endpoint, _ := startMinIO(t)
	objects, err := policy.NewS3(ctx, policy.S3Config{Endpoint: endpoint, Bucket: "strata-bundles", AccessKey: "strata", SecretKey: "strata-e2e-secret"})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = 7
	}
	key := filepath.Join(dir, "example.key")
	if err = os.WriteFile(key, seed, 0600); err != nil {
		t.Fatal(err)
	}
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	rules := filepath.Join(dir, "rules.yaml")
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
 - id: 700012
   name: example XSS
   layer: managed
   stage: request_headers
   score: 100
   severity: critical
   match:
     all:
      - targets: [{var: args}]
        operator: {type: detect_xss}
   metadata: {source: organization, license: Apache-2.0}
`
	if err = os.WriteFile(rules, []byte(ir), 0600); err != nil {
		t.Fatal(err)
	}
	compiler := &policy.Compiler{Binary: compilerBin, KeyFile: key, Rules: []string{rules}, StagingStore: st, CostBudget: policy.DefaultCostBudget}
	presence := fleet.NewPresence()
	rollouts := fleet.NewRollouts(st, presence, []float64{1}, 0)
	go rollouts.Run(ctx)
	caFile, caKey, cert, tlsKey := fleetPKI(t, dir)
	ca, err := fleet.LoadCA(caFile, caKey)
	if err != nil {
		t.Fatal(err)
	}
	tlsConfig, err := fleet.ServerTLS(caFile, cert, tlsKey)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatal(err)
	}
	svc := ingest.NewIngestService(events, ingest.DefaultBatcherConfig(), time.Hour)
	svc.Gate = st
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := svc.Close(cleanup); err != nil {
			t.Error(err)
		}
	})
	gs := fleet.NewGRPCServer(tlsConfig, fleet.NewServer(fleet.Config{Ingest: svc, Registry: st, CA: ca, TrustBundle: trust, BundlePubKey: pub, Presence: presence, Objects: objects, Rollouts: rollouts}))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- gs.Serve(listener) }()
	t.Cleanup(func() {
		gs.Stop()
		if err := <-serveDone; err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			t.Error("Fleet serve:", err)
		}
	})
	corpus := filepath.Join(dir, "corpus.parquet")
	repo, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	if out, err := exec.CommandContext(ctx, replayBin, "gen", "--out", corpus, "--count", "4300", "--corpus", filepath.Join(repo, "corpus")).CombinedOutput(); err != nil {
		t.Fatalf("real corpus: %v %s", err, out)
	}
	runner := &replay.Runner{Store: st, Deployable: st.DeployablePolicies, Prepare: compiler.Prepare, Build: replay.ReplayBuilder(*compiler), Binary: replayBin, Corpus: corpus, BaselinePub: pub, Timeout: 2 * time.Minute,
		Baseline: func(c context.Context) ([]byte, uint64, error) {
			b, err := st.LatestBundle(c)
			if err != nil {
				return nil, 0, err
			}
			data, err := objects.Get(c, b.ObjectKey)
			return data, b.Version, err
		}}
	if err = runner.Init(); err != nil {
		t.Fatal(err)
	}
	issuer := authtest.New(t)
	verifier, err := auth.NewVerifier(ctx, auth.Config{Issuer: issuer.URL, Audience: authtest.Audience})
	if err != nil {
		t.Fatal(err)
	}
	deployer := &policy.Deployer{Store: st, Builder: compiler, Objects: objects, PubKey: pub, Publish: rollouts.Start, VerifyReplay: (replay.Gate{Store: st}).Check}
	adm, err := admin.New(ctx, verifier, admin.BuildInfo{Version: "example-m4"}, admin.Deps{Fleet: st, Presence: presence, Policies: st, Deployer: deployer, Rollouts: st, Kicker: rollouts, Operations: st, ReplayKick: runner.Kick, ReplayApproved: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(adm.Close)
	health := rulehealth.NewService(events, st)
	rest := api.NewServer(api.ServerConfig{Auth: verifier, Admin: adm.Gateway, Annotations: st, Health: health, StagingNotices: st}, events).Handler()
	p := &platform{fleetEnv: &fleetEnv{st: st, addr: listener.Addr().String(), rest: rest, issuer: issuer, caFile: caFile, presence: presence}, pub: pub}
	return &automaticPlatform{platform: p, events: events, runner: runner, compiler: compiler, objects: objects, rollouts: rollouts}
}

type nativeReply struct {
	Status                  int
	Action, Rules, ID, Body string
}

func nativeGet(t *testing.T, client *http.Client, base, query string) nativeReply {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), "GET", base+query, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "api.example.test"
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 8192))
	if err != nil {
		t.Fatal(err)
	}
	return nativeReply{res.StatusCode, res.Header.Get("X-Example-Action"), res.Header.Get("X-Example-Rules"), res.Header.Get("X-Example-Event"), string(body)}
}

func startAutomaticNginx(t *testing.T, nd *node, pub []byte, nginx, module, output string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "logs"), 0755); err != nil {
		t.Fatal(err)
	}
	pubFile := filepath.Join(dir, "bundle.pub")
	if err := os.WriteFile(pubFile, pub, 0600); err != nil {
		t.Fatal(err)
	}
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "example-origin-reached") }))
	t.Cleanup(origin.Close)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err = listener.Close(); err != nil {
		t.Fatal(err)
	}
	conf := fmt.Sprintf(`load_module %q;
daemon off;
worker_processes 2;
pid %q;
error_log %q notice;
events { worker_connections 128; }
http {
 access_log off;
 client_body_temp_path %q;
 proxy_temp_path %q;
 fastcgi_temp_path %q;
 uwsgi_temp_path %q;
 scgi_temp_path %q;
 strata_control_file %q;
 strata_bundle_dir %q;
 strata_bundle_pubkey %q;
 strata_node_id %q;
 strata_metrics_file %q;
 strata_event_socket %q;
 server { listen %s;
  location / { strata on; strata_policy example-api; strata_cpu_budget 10ms; strata_fail_mode open;
   add_header X-Example-Action $strata_action always;
   add_header X-Example-Rules $strata_rules always;
   add_header X-Example-Event $strata_block_id always;
   proxy_pass %s;
  }
 }
}
`, module, filepath.Join(dir, "nginx.pid"), filepath.Join(output, "nginx-error.log"), filepath.Join(dir, "body"), filepath.Join(dir, "proxy"), filepath.Join(dir, "fastcgi"), filepath.Join(dir, "uwsgi"), filepath.Join(dir, "scgi"), nd.control, nd.bundles, pubFile, nd.id, filepath.Join(nd.dir, "metrics"), "unix:"+filepath.Join(nd.dir, "events.sock"), address, origin.URL)
	file := filepath.Join(dir, "nginx.conf")
	if err = os.WriteFile(file, []byte(conf), 0600); err != nil {
		t.Fatal(err)
	}
	logFile, err := os.Create(filepath.Join(output, "nginx-process.log"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = logFile.Close() })
	cmd := exec.Command(nginx, "-p", dir+"/", "-c", file)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.Env = append(os.Environ(), "ASAN_OPTIONS=detect_leaks=0:detect_odr_violation=0:abort_on_error=1:log_path="+filepath.Join(output, "asan"), "UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1:log_path="+filepath.Join(output, "ubsan"))
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Signal(syscall.SIGQUIT)
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case err := <-done:
			if err != nil {
				t.Error("NGINX:", err)
			}
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			<-done
			t.Error("NGINX stop timed out")
		}
	})
	waitFor(t, "native listener", 10*time.Second, func() bool {
		c, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err != nil {
			return false
		}
		_ = c.Close()
		return true
	})
	return "http://" + address
}

func TestAutomaticStagingInRealNginx(t *testing.T) {
	compiler, replayBin, nginx, module, output := os.Getenv("STRATA_TEST_COMPILER"), os.Getenv("STRATA_TEST_REPLAY_BIN"), os.Getenv("STRATA_TEST_NGINX"), os.Getenv("STRATA_TEST_NGINX_MODULE"), os.Getenv("STRATA_M4_EVIDENCE_DIR")
	if compiler == "" || replayBin == "" || nginx == "" || module == "" || output == "" {
		t.Skip("real M4 compiler/replay/NGINX/isolated evidence paths not configured")
	}
	if err := os.Mkdir(output, 0755); err != nil {
		t.Fatal("new evidence directory required:", err)
	}
	p := startAutomaticPlatform(t, compiler, replayBin)
	ctx := t.Context()
	bin := buildAgentBinary(t)
	nd := p.enrollNodes(t, bin, 1)[0]
	nd.start(t, bin, p.addr, "--metrics-file", filepath.Join(nd.dir, "metrics"))
	defer func() {
		if t.Failed() {
			t.Logf("private agent log:\n%s", nd.proc.logBuf.String())
		}
	}()
	body := `{"id":"example-api","name":"example-api","spec":{"mode":"MODE_ENFORCE","auto_staging":{"enabled":true,"rule_ids":[700011],"window_seconds":300,"min_matches":100,"min_reports":5,"fp_threshold_bps":500}}}`
	if code := p.call(t, "operator", "POST", "/v1/policies", body, nil); code != 200 {
		t.Fatalf("create policy: %d", code)
	}
	op, err := p.st.LatestReplay(ctx, "example-api", 1)
	if err != nil {
		t.Fatal(err)
	}
	if !p.runner.RunOnce(ctx) {
		t.Fatal("draft replay not queued")
	}
	op, err = p.st.GetOperation(ctx, op.ID)
	if err != nil || op.State != store.OpDone {
		t.Fatalf("real replay: %s %v %s", op.State, err, op.Error)
	}
	var report replay.Report
	if err = json.Unmarshal(op.Result, &report); err != nil || report.Samples() != 4300 || report.Corpus == nil || report.Corpus.NewlyBlocked == 0 {
		t.Fatalf("real proof corpus: %+v %v", report.Corpus, err)
	}
	if code := p.call(t, "operator", "POST", "/v1/policies/example-api:submit", `{"version":1}`, nil); code != 200 {
		t.Fatal("submit:", code)
	}
	if code := p.call(t, "operator", "POST", "/v1/policies/example-api:deploy", `{}`, nil); code < 300 {
		t.Fatal("unapproved source deployed")
	}
	if code := p.call(t, "approver", "POST", "/v1/policies/example-api:approve", `{"version":1}`, nil); code != 200 {
		t.Fatal("independent approval:", code)
	}
	if code := p.call(t, "operator", "POST", "/v1/policies/example-api:deploy", `{}`, nil); code != 200 {
		t.Fatal("source deployment:", code)
	}
	waitFor(t, "source agent ACTIVE", 30*time.Second, func() bool { ready, err := p.st.StagingSourceReady(ctx, 1); return err == nil && ready })
	base := startAutomaticNginx(t, nd, p.pub, nginx, module, output)
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	defer client.CloseIdleConnections()
	sql := "/query?id=" + url.QueryEscape("-1 UNION SELECT 'example-marker'--")
	xss := "/query?id=1&x=" + url.QueryEscape("<script>alert(1)</script>")
	ids := make([]string, 0, 100)
	replies := make([]nativeReply, 0, 5)
	for i := 0; i < 100; i++ {
		r := nativeGet(t, client, base, sql)
		if r.Status != 403 || r.Action != "block" || !strings.HasPrefix(r.ID, "STR-") || !strings.Contains(r.Rules, "700011") {
			t.Fatalf("source SQLi: %+v", r)
		}
		ids = append(ids, r.ID)
		if i == 0 {
			replies = append(replies, r)
		}
	}
	healthy := nativeGet(t, client, base, xss)
	if healthy.Status != 403 || healthy.Action != "block" || !strings.Contains(healthy.Rules, "700012") {
		t.Fatalf("source XSS: %+v", healthy)
	}
	replies = append(replies, healthy)
	waitFor(t, "100 actual matched events through socket/agent/mTLS/ClickHouse", 30*time.Second, func() bool {
		n, err := p.events.RuleMatchCount(ctx, 700011, "example-api", 1, time.Now().Add(-5*time.Minute), time.Now())
		if err != nil {
			t.Fatalf("source match query: %v", err)
		}
		return n == 100
	})
	if info, err := os.Stat(filepath.Join(nd.dir, "metrics")); err != nil || info.Size() == 0 {
		t.Fatalf("real metrics missing: %v", err)
	}
	fallbackBefore := strings.Count(nd.proc.logBuf.String(), "no worker metrics")
	health := rulehealth.NewService(p.events, p.st)
	writer := &policy.StagingDeployer{Store: p.st, Compiler: p.compiler, Objects: p.objects, PubKey: p.pub, VerifySource: (replay.Gate{Store: p.st}).CheckStaging, Observe: health.Observe}
	workerCtx, stop := context.WithCancel(ctx)
	defer stop()
	worker := &rulehealth.StagingWorker{Store: p.st, Writer: writer, Evaluate: health.Evaluate, Publish: p.rollouts.StartStaging}
	go worker.Run(workerCtx)
	for _, id := range ids[:5] {
		if code := p.call(t, "operator", "POST", "/v1/events/"+id+":markFalsePositive", `{"reason":"synthetic legitimate request"}`, nil); code != 200 {
			t.Fatal("report actual event FP:", code)
		}
	}
	spikeAt := time.Now()
	waitFor(t, "derived bundle ACTIVE via worker metrics", 4*time.Minute, func() bool { ready, err := p.st.StagingSourceReady(ctx, 2); return err == nil && ready })
	staged := nativeGet(t, client, base, sql)
	elapsed := time.Since(spikeAt)
	if elapsed >= 5*time.Minute || staged.Status != 200 || staged.Action != "log" || !strings.HasPrefix(staged.ID, "EVT-") || staged.Body != "example-origin-reached" {
		t.Fatalf("actual staging after %s: %+v", elapsed, staged)
	}
	replies = append(replies, staged)
	healthy = nativeGet(t, client, base, xss)
	if healthy.Status != 403 || healthy.Action != "block" || !strings.Contains(healthy.Rules, "700012") {
		t.Fatalf("healthy rule weakened: %+v", healthy)
	}
	replies = append(replies, healthy)
	mixed := nativeGet(t, client, base, sql+"&x="+url.QueryEscape("<script>alert(1)</script>"))
	if mixed.Status != 403 || mixed.Action != "block" || !strings.HasPrefix(mixed.ID, "STR-") || !strings.Contains(mixed.Rules, "700012") {
		t.Fatalf("mixed request bypassed healthy rule: %+v", mixed)
	}
	replies = append(replies, mixed)
	if strings.Count(nd.proc.logBuf.String(), "no worker metrics") != fallbackBefore {
		t.Fatal("derived ACTIVE used missing-metrics fallback")
	}
	waitFor(t, "actual staged EVT persisted", 10*time.Second, func() bool {
		event, err := p.events.GetEvent(ctx, staged.ID)
		return err == nil && event.PolicyVersion == 2 && event.Action == "shadow"
	})
	var notices struct {
		Notices []store.StagingNotice `json:"notices"`
	}
	if code := p.call(t, "approver", "GET", "/v1/rules/staging-actions", "", &notices); code != 200 || len(notices.Notices) != 1 || notices.Notices[0].RuleID != 700011 || notices.Notices[0].RolloutState != "DONE" {
		t.Fatalf("reviewer notice: %d %+v", code, notices)
	}
	latest, err := p.st.LatestBundle(ctx)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := os.ReadFile(filepath.Join(nd.bundles, "bundle-2.sbn"))
	if err != nil {
		t.Fatal(err)
	}
	if h, err := bundlefmt.Verify(artifact, p.pub); err != nil || h.Version != 2 {
		t.Fatalf("installed signature: %+v %v", h, err)
	}
	for _, prefix := range []string{"asan.*", "ubsan.*"} {
		files, err := filepath.Glob(filepath.Join(output, prefix))
		if err != nil || len(files) != 0 {
			t.Fatalf("sanitizer reports: %v %v", files, err)
		}
	}
	hashFile := func(path string) string {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		h := sha256.Sum256(b)
		return hex.EncodeToString(h[:])
	}
	evidence := map[string]any{"elapsed_seconds": elapsed.Seconds(), "source_matched_events": 100, "first_fp_reports": 5, "http_before_after": replies, "replay": report, "notice": notices.Notices[0], "derived_bundle_sha256": hex.EncodeToString(latest.SHA256), "binary_sha256": map[string]string{"compiler": hashFile(compiler), "replay": hashFile(replayBin), "nginx": hashFile(nginx), "module": hashFile(module), "agent": hashFile(bin)}, "derived_ack_missing_metrics_fallback": false, "scope": "private synthetic 2-rule policy, real replay/approval/socket/agent/mTLS/ClickHouse/signed hot reload; not production or load SLO"}
	raw, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(output, "result.json"), append(raw, '\n'), 0644); err != nil {
		t.Fatal(err)
	}
	t.Logf("PASS real FP → signed hot reload: %s, SQLi 403/block → 200/log/EVT; XSS stays 403/block; real metrics ACK and reviewer notice", elapsed)
}
