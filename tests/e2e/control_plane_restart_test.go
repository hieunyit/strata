package e2e

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/strata/strata/agent/pkg/bundlefmt"
	"github.com/strata/strata/control-plane/auth/authtest"
	"github.com/strata/strata/control-plane/policy"
	"github.com/strata/strata/control-plane/store"
)

func restartAddress(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := ln.Addr().String()
	if err = ln.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

func restartBinary(t *testing.T, module, target string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), target)
	cmd := exec.CommandContext(t.Context(), "go", "build", "-race", "-o", path, "./cmd/"+target)
	cmd.Dir = filepath.Join("..", "..", module)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v %s", module, err, out)
	}
	return path
}

type restartProcess struct {
	cmd    *exec.Cmd
	done   chan error
	log    *syncBuffer
	reaped bool
}

func restartStart(t *testing.T, binary string, env, args []string) *restartProcess {
	t.Helper()
	p := &restartProcess{cmd: exec.Command(binary, args...), done: make(chan error, 1), log: &syncBuffer{}}
	p.cmd.Env, p.cmd.Stdout, p.cmd.Stderr = env, p.log, p.log
	if err := p.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { p.done <- p.cmd.Wait() }()
	t.Cleanup(func() {
		if !p.reaped {
			_ = p.cmd.Process.Signal(syscall.SIGTERM)
			select {
			case err := <-p.done:
				if err != nil {
					t.Error("control plane cleanup:", err)
				}
			case <-time.After(10 * time.Second):
				_ = p.cmd.Process.Kill()
				<-p.done
				t.Error("control plane cleanup deadline")
			}
			p.reaped = true
		}
		if t.Failed() {
			t.Logf("owned control-plane log:\n%s", p.log.String())
		}
	})
	return p
}

func (p *restartProcess) kill(t *testing.T) {
	t.Helper()
	if err := p.cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-p.done:
		p.reaped = true
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			t.Fatalf("expected killed process, got %v", err)
		}
		status, ok := exit.Sys().(syscall.WaitStatus)
		if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
			t.Fatalf("not SIGKILL: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("control-plane SIGKILL did not exit")
	}
}

// Uses the production server entrypoint in a separate process, not a restarted
// in-process gRPC fixture. Dependencies and credentials belong to this test.
func TestControlPlaneProcessRestartWithRealNginx(t *testing.T) {
	testControlPlaneProcessRestart(t, false)
}

func TestControlPlaneCrashBetweenIngestCommits(t *testing.T) {
	testControlPlaneProcessRestart(t, true)
}

func testControlPlaneProcessRestart(t *testing.T, commitBarrier bool) {
	compiler, nginx, module, output := os.Getenv("STRATA_TEST_COMPILER"), os.Getenv("STRATA_TEST_NGINX"), os.Getenv("STRATA_TEST_NGINX_MODULE"), os.Getenv("STRATA_CP_RESTART_EVIDENCE_DIR")
	if commitBarrier {
		output = os.Getenv("STRATA_CP_COMMIT_EVIDENCE_DIR")
	}
	if compiler == "" || nginx == "" || module == "" || output == "" {
		t.Skip("owned native restart fixture not configured")
	}
	if err := os.Mkdir(output, 0755); err != nil {
		t.Fatal("new evidence directory required:", err)
	}
	ctx := t.Context()
	pool := startPostgres(t)
	events, ch := losslessClickHouseConfig(t)
	schema, err := os.ReadFile(filepath.Join("..", "..", "control-plane", "ingest", "schema.sql"))
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range strings.Split(string(schema), ";") {
		if strings.TrimSpace(stmt) != "" {
			if err := events.Conn().Exec(ctx, stmt); err != nil {
				t.Fatal(err)
			}
		}
	}
	dir := t.TempDir()
	ca, caKey, cert, key := fleetPKI(t, dir)
	seed := make([]byte, ed25519.SeedSize)
	copy(seed, "example-process-restart-fixture")
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	pubFile, seedFile := filepath.Join(dir, "bundle.pub"), filepath.Join(dir, "bundle.key")
	for path, data := range map[string][]byte{pubFile: pub, seedFile: seed} {
		if err = os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	// A signed preinstalled one-rule fixture isolates recovery from deployment.
	// It does not attest replay, approval or rollout (covered by the M4 chain).
	rules := filepath.Join(dir, "rules.yaml")
	if err = os.WriteFile(rules, []byte(`ir_version: 1
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
`), 0600); err != nil {
		t.Fatal(err)
	}
	fixture := &policy.Compiler{Binary: compiler, KeyFile: seedFile, Rules: []string{rules}, CostBudget: policy.DefaultCostBudget}
	bundle, err := fixture.Build(ctx, 1, []policy.Named{{Name: "example-api", Spec: policy.Spec{Mode: "enforce"}}})
	if err != nil {
		t.Fatal(err)
	}
	if header, err := bundlefmt.Verify(bundle, pub); err != nil || header.Version != 1 {
		t.Fatalf("signed fixture: %+v %v", header, err)
	}
	cpBin, agentBin := restartBinary(t, "control-plane", "server"), restartBinary(t, "agent", "strata-agent")
	restAddr, fleetAddr, metricsAddr := restartAddress(t), restartAddress(t), restartAddress(t)
	issuer := authtest.New(t)
	args := []string{"-addr", restAddr, "-grpc-addr", fleetAddr, "-clickhouse-addr", ch.Addr, "-clickhouse-user", ch.Username,
		"-tls-ca", ca, "-tls-cert", cert, "-tls-key", key, "-node-ca-cert", ca, "-node-ca-key", caKey, "-bundle-pubkey", pubFile,
		"-oidc-issuer", issuer.URL, "-oidc-audience", authtest.Audience}
	// No inherited STRATA_*, Vault credentials or external service config.
	env := []string{"PATH=" + os.Getenv("PATH"), "GOMAXPROCS=4", "STRATA_POSTGRES_DSN=" + pool.Config().ConnString(), "STRATA_CLICKHOUSE_PASSWORD=" + ch.Password}
	first := restartStart(t, cpBin, env, args)
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	defer client.CloseIdleConnections()
	ready := func() bool {
		r, err := client.Get("http://" + restAddr + "/healthz")
		if err != nil {
			return false
		}
		_ = r.Body.Close()
		return r.StatusCode == http.StatusNoContent
	}
	waitFor(t, "first real control plane", 30*time.Second, ready)
	restURL, err := url.Parse("http://" + restAddr)
	if err != nil {
		t.Fatal(err)
	}
	p := &platform{fleetEnv: &fleetEnv{st: store.New(pool), addr: fleetAddr, rest: httputil.NewSingleHostReverseProxy(restURL), issuer: issuer, caFile: ca}, pub: pub}
	nd := p.enrollNodes(t, agentBin, 1)[0]
	if err = os.MkdirAll(nd.bundles, 0755); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(nd.bundles, "bundle-1.sbn"), bundle, 0600); err != nil {
		t.Fatal(err)
	}
	writeControl(t, nd.control)
	nd.start(t, agentBin, fleetAddr, "--metrics-file", filepath.Join(nd.dir, "metrics"), "--metrics-addr", metricsAddr)
	defer func() {
		if t.Failed() {
			t.Logf("owned agent log:\n%s", nd.proc.logBuf.String())
		}
	}()
	waitFor(t, "agent online", 30*time.Second, func() bool { return p.node(t, nd.id).Online })
	if err := waitForSocket(filepath.Join(nd.dir, "events.sock"), 5*time.Second); err != nil {
		t.Fatal(err)
	}
	base := startAutomaticNginx(t, nd, pub, nginx, module, output)
	metrics := func() map[string]uint64 {
		r, err := client.Get("http://" + metricsAddr + "/metrics")
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		raw, err := io.ReadAll(io.LimitReader(r.Body, 128<<10))
		if err != nil || r.StatusCode != 200 {
			t.Fatalf("agent metrics: %d %v", r.StatusCode, err)
		}
		m := map[string]uint64{}
		for _, line := range strings.Split(string(raw), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 2 && strings.HasPrefix(fields[0], "strata_agent_") {
				if n, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
					m[fields[0]] = n
				}
			}
		}
		for _, key := range []string{"events_received_total", "events_invalid_total", "events_truncated_total", "spool_dropped_events_total", "spool_unacked_batches", "spool_last_seq", "acked_seq"} {
			if _, ok := m["strata_agent_"+key]; !ok {
				t.Fatal("missing metric:", key)
			}
		}
		return m
	}
	ids := make([]string, 0, 141)
	var panicID string
	phases := map[string][]nativeReply{}
	send := func(phase string, n int) {
		benign := nativeGet(t, client, base, "/query?id=1")
		if benign.Status != 200 || benign.Action != "allow" || benign.Body != "example-origin-reached" {
			t.Fatalf("%s benign: %+v", phase, benign)
		}
		phases[phase] = append(phases[phase], benign)
		for i := 0; i < n; i++ {
			r := nativeGet(t, client, base, "/query?id="+url.QueryEscape("-1 UNION SELECT 'example-marker'--"))
			if r.Status != 403 || r.Action != "block" || !strings.HasPrefix(r.ID, "STR-") || !strings.Contains(r.Rules, "700011") {
				t.Fatalf("%s SQLi: %+v", phase, r)
			}
			ids = append(ids, r.ID)
			if i == 0 {
				phases[phase] = append(phases[phase], r)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	count := func() uint64 {
		var n uint64
		if err := events.Conn().QueryRow(ctx, "SELECT count() FROM events FINAL WHERE node_id=?", nd.id).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	watermark := func() uint64 {
		var n uint64
		if err := pool.QueryRow(ctx, "SELECT last_seq FROM ingest_sequences WHERE node_id=$1", nd.id).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	send("before", 20)
	waitFor(t, "before events durable and ACKed", 15*time.Second, func() bool { return count() == 20 && metrics()["strata_agent_spool_unacked_batches"] == 0 })
	// This metric counts all datagrams, including policy counters; exact event
	// coverage is verified by every native HTTP event ID in ClickHouse below.
	before := metrics()
	committed := watermark()
	if committed == 0 {
		t.Fatal("no durable initial watermark")
	}
	controlBefore, err := os.ReadFile(nd.control)
	if err != nil {
		t.Fatal(err)
	}
	var killedAt time.Time
	persistedBeforeCrash := uint64(20)
	commitFault := map[string]any{}
	if commitBarrier {
		// Only this test's disposable database is modified. The real server
		// writes ClickHouse, then blocks inside its watermark UPDATE trigger.
		// Killing it here tests the two-database commit window without a
		// production hook, fake event producer, or mocked acknowledgement.
		barrier, err := pool.Acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer barrier.Release()
		const lockKey = int64(123456789)
		locked := false
		unlock := func() {
			if !locked {
				return
			}
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var ok bool
			if e := barrier.QueryRow(cleanup, "SELECT pg_advisory_unlock($1)", lockKey).Scan(&ok); e != nil || !ok {
				t.Errorf("release owned commit barrier: %v %v", ok, e)
			}
			locked = false
		}
		defer unlock()
		if _, err = barrier.Exec(ctx, "SELECT pg_advisory_lock($1)", lockKey); err != nil {
			t.Fatal(err)
		}
		locked = true
		if _, err = pool.Exec(ctx, `CREATE FUNCTION test_ingest_commit_barrier() RETURNS trigger LANGUAGE plpgsql AS $$
			BEGIN PERFORM pg_advisory_xact_lock(123456789); RETURN NEW; END $$;
			CREATE TRIGGER test_ingest_commit_barrier BEFORE UPDATE ON ingest_sequences FOR EACH ROW EXECUTE FUNCTION test_ingest_commit_barrier()`); err != nil {
			t.Fatal(err)
		}
		send("between_commits", 20)
		waitFor(t, "real CH insert committed and CP blocked before PG watermark", 15*time.Second, func() bool {
			var blocked bool
			if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND $1=ANY(pg_blocking_pids(pid)))`, barrier.Conn().PgConn().PID()).Scan(&blocked); err != nil {
				t.Fatal(err)
			}
			return blocked && count() > 20
		})
		persistedBeforeCrash = count()
		if watermark() != committed || metrics()["strata_agent_acked_seq"] != before["strata_agent_acked_seq"] || metrics()["strata_agent_spool_unacked_batches"] == 0 {
			t.Fatal("watermark/ACK advanced before commit barrier released")
		}
		commitFault = map[string]any{"ch_logical_rows_before_crash": persistedBeforeCrash, "pg_sequence_before_crash": watermark(), "ack_before_crash": metrics()["strata_agent_acked_seq"], "pg_lock_wait_observed": true}
		killedAt = time.Now()
		first.kill(t)
		unlock()
		if _, err = pool.Exec(ctx, `DROP TRIGGER test_ingest_commit_barrier ON ingest_sequences; DROP FUNCTION test_ingest_commit_barrier()`); err != nil {
			t.Fatal(err)
		}
	} else {
		killedAt = time.Now()
		first.kill(t)
	}
	if ready() {
		t.Fatal("REST survived killed control-plane process")
	}
	send("during", 80)
	if commitBarrier {
		// The deliberate test-hook panic is caught by the real FFI. Its
		// error event must survive the same CP outage and durable spool.
		r := nativeGet(t, client, base, "/query?STRATA-TEST-PANIC")
		if r.Status != 200 || r.Action != "error" || !strings.HasPrefix(r.ID, "EVT-") {
			t.Fatalf("native panic while CP absent: %+v", r)
		}
		panicID = r.ID
		ids = append(ids, panicID)
		phases["panic_without_cp"] = []nativeReply{r}
	}
	waitFor(t, "spooled while CP absent", 5*time.Second, func() bool {
		return metrics()["strata_agent_events_received_total"] >= uint64(len(ids)) && metrics()["strata_agent_spool_unacked_batches"] > 0
	})
	during := metrics()
	if count() != persistedBeforeCrash || watermark() != committed || during["strata_agent_acked_seq"] != before["strata_agent_acked_seq"] {
		t.Fatal("events/ACK advanced while CP was dead")
	}
	second := restartStart(t, cpBin, env, args)
	if second.cmd.Process.Pid == first.cmd.Process.Pid {
		t.Fatal("process identity did not change")
	}
	waitFor(t, "restarted control plane", 30*time.Second, ready)
	restoredAt := time.Now()
	waitFor(t, "agent reconnected automatically", 30*time.Second, func() bool { return p.node(t, nd.id).Online })
	send("after", 20)
	recovered := waitFor(t, "all real NGINX IDs durable and spool drained", 45*time.Second, func() bool {
		return count() == uint64(len(ids)) && metrics()["strata_agent_spool_unacked_batches"] == 0
	})
	after := metrics()
	for _, key := range []string{"events_invalid_total", "events_truncated_total", "spool_dropped_events_total"} {
		if after["strata_agent_"+key] != 0 {
			t.Fatal("nonzero error metric:", key)
		}
	}
	if after["strata_agent_events_received_total"] < uint64(len(ids)) || watermark() <= committed {
		t.Fatal("event count/watermark not recovered")
	}
	unique := make(map[string]bool, len(ids))
	for _, id := range ids {
		if unique[id] {
			t.Fatal("duplicate generated Block ID:", id)
		}
		unique[id] = true
		event, err := events.GetEvent(ctx, id)
		if id == panicID {
			if err != nil || event.NodeID != nd.id || event.PolicyVersion != 1 || event.Action != "error" || len(event.MatchedRules) != 0 {
				t.Fatalf("persisted native panic event: %+v %v", event, err)
			}
			continue
		}
		if err != nil || event.NodeID != nd.id || event.PolicyVersion != 1 || event.Action != "block" || len(event.MatchedRules) != 1 || event.MatchedRules[0] != 700011 {
			t.Fatalf("persisted native event %s: %+v %v", id, event, err)
		}
	}
	controlAfter, err := os.ReadFile(nd.control)
	if err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(controlBefore) != sha256.Sum256(controlAfter) {
		t.Fatal("last-known-good control changed during outage")
	}
	installed, err := os.ReadFile(filepath.Join(nd.bundles, "bundle-1.sbn"))
	if err != nil || sha256.Sum256(installed) != sha256.Sum256(bundle) {
		t.Fatal("installed bundle changed:", err)
	}
	if _, err = bundlefmt.Verify(installed, pub); err != nil {
		t.Fatal(err)
	}
	var physical uint64
	if err := events.Conn().QueryRow(ctx, "SELECT count() FROM events WHERE node_id=?", nd.id).Scan(&physical); err != nil {
		t.Fatal(err)
	}
	hashes := map[string]string{}
	for label, path := range map[string]string{"control_plane": cpBin, "agent": agentBin, "compiler": compiler, "nginx": nginx, "module": module} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		hashes[label] = hex.EncodeToString(sum[:])
	}
	for _, pat := range []string{"asan.*", "ubsan.*"} {
		reports, err := filepath.Glob(filepath.Join(output, pat))
		if err != nil || len(reports) != 0 {
			t.Fatalf("sanitizer reports: %v %v", reports, err)
		}
	}
	evidence := map[string]any{"commit_barrier": commitFault, "commit_window_exercised": commitBarrier, "native_panic_event_id": panicID, "fault": "SIGKILL actual control-plane server, restart same addresses/config/databases", "outage_seconds": restoredAt.Sub(killedAt).Seconds(), "post_send_drain_seconds": recovered.Seconds(), "before": before, "during": during, "after": after, "before_durable_sequence": committed, "after_durable_sequence": watermark(), "nginx_event_ids": ids, "logical_events": len(ids), "physical_rows": physical, "http_examples": phases, "binary_sha256": hashes, "scope": "single node, signed preinstalled one-rule fixture; serial native requests, optional proven CH-commit/PG-watermark crash barrier; not full game day or production throughput"}
	raw, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(output, "result.json"), append(raw, '\n'), 0644); err != nil {
		t.Fatal(err)
	}
	t.Logf("PASS CP process SIGKILL/restart: %d/%d native event IDs persisted, physical rows=%d, outage=%s, last-known-good bundle unchanged", len(unique), len(ids), physical, restoredAt.Sub(killedAt))
}
