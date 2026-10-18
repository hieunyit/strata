package e2e

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/strata/strata/agent/pkg/bundlefmt"
	"github.com/strata/strata/control-plane/store"
)

// Corrupts the real private MinIO object after normal deploy verification and
// recording, before rollout notification. No agent/Fleet verifier is mocked.
func TestCorruptedArtifactKeepsNativeLastKnownGood(t *testing.T) {
	compiler, replayBin, nginx, module, output := os.Getenv("STRATA_TEST_COMPILER"), os.Getenv("STRATA_TEST_REPLAY_BIN"), os.Getenv("STRATA_TEST_NGINX"), os.Getenv("STRATA_TEST_NGINX_MODULE"), os.Getenv("STRATA_CORRUPT_EVIDENCE_DIR")
	if compiler == "" || replayBin == "" || nginx == "" || module == "" || output == "" {
		t.Skip("private native corrupted-artifact fixture not configured")
	}
	if err := os.Mkdir(output, 0755); err != nil {
		t.Fatal("new evidence directory required:", err)
	}
	p := startAutomaticPlatform(t, compiler, replayBin)
	ctx := t.Context()
	bin := restartBinary(t, "agent", "strata-agent")
	nd := p.enrollNodes(t, bin, 1)[0]
	metricsAddr := restartAddress(t)
	nd.start(t, bin, p.addr, "--metrics-file", filepath.Join(nd.dir, "metrics"), "--metrics-addr", metricsAddr)
	defer func() {
		if t.Failed() {
			t.Logf("owned agent log:\n%s", nd.proc.logBuf.String())
		}
	}()

	// Every recovery version is replayed and independently approved through the
	// real admin API. A failed rollout is not silently retried or marked active.
	deploy := func(version int, mode string) string {
		var body string
		if version == 1 {
			body = fmt.Sprintf(`{"id":"example-api","name":"example-api","spec":{"mode":%q}}`, mode)
			if c := p.call(t, "operator", "POST", "/v1/policies", body, nil); c != 200 {
				t.Fatal("create:", c)
			}
		} else {
			var current struct {
				Policy struct {
					Etag string `json:"etag"`
				} `json:"policy"`
			}
			if c := p.call(t, "viewer", "GET", "/v1/policies/example-api", "", &current); c != 200 || current.Policy.Etag == "" {
				t.Fatal("current policy:", c)
			}
			body = fmt.Sprintf(`{"etag":%q,"spec":{"mode":%q}}`, current.Policy.Etag, mode)
			if c := p.call(t, "operator", "PATCH", "/v1/policies/example-api", body, nil); c != 200 {
				t.Fatal("patch:", c)
			}
		}
		op, err := p.st.LatestReplay(ctx, "example-api", version)
		if err != nil || !p.runner.RunOnce(ctx) {
			t.Fatal("queued replay:", err)
		}
		op, err = p.st.GetOperation(ctx, op.ID)
		if err != nil || op.State != store.OpDone {
			t.Fatalf("real replay: %s %s %v", op.State, op.Error, err)
		}
		if c := p.call(t, "operator", "POST", "/v1/policies/example-api:submit", fmt.Sprintf(`{"version":%d}`, version), nil); c != 200 {
			t.Fatal("submit:", c)
		}
		if c := p.call(t, "approver", "POST", "/v1/policies/example-api:approve", fmt.Sprintf(`{"version":%d,"expected_replay_id":%q}`, version, op.ID), nil); c != 200 {
			t.Fatal("approve:", c)
		}
		var result struct {
			RolloutID string `json:"rollout_id"`
		}
		if c := p.call(t, "operator", "POST", "/v1/policies/example-api:deploy", `{}`, &result); c != 200 || result.RolloutID == "" {
			t.Fatal("deploy:", c)
		}
		return result.RolloutID
	}
	r1 := deploy(1, "MODE_ENFORCE")
	waitFor(t, "installed good bundle 1", 30*time.Second, func() bool { return nd.controlVersion() == 1 })
	base := startAutomaticNginx(t, nd, p.pub, nginx, module, output)
	waitFor(t, "good rollout 1 DONE", 30*time.Second, func() bool { return p.rollout(t, r1).Rollout.State == "DONE" })
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	defer client.CloseIdleConnections()
	metrics := func() map[string]uint64 {
		req, err := http.NewRequestWithContext(ctx, "GET", "http://"+metricsAddr+"/metrics", nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		data, err := io.ReadAll(io.LimitReader(response.Body, 128<<10))
		if err != nil || response.StatusCode != 200 {
			t.Fatal("agent metrics:", response.StatusCode, err)
		}
		values := map[string]uint64{}
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) != 2 || !strings.HasPrefix(fields[0], "strata_agent_") {
				continue
			}
			switch fields[0] {
			case "strata_agent_bundle_active_version", "strata_agent_spool_unacked_batches", "strata_agent_spool_last_seq", "strata_agent_acked_seq", "strata_agent_events_invalid_total", "strata_agent_events_truncated_total", "strata_agent_spool_dropped_events_total":
				value, err := strconv.ParseUint(fields[1], 10, 64)
				if err != nil {
					t.Fatal("invalid metric:", fields[0], err)
				}
				values[fields[0]] = value
			}
		}
		if len(values) != 7 {
			t.Fatal("missing agent metrics:", values)
		}
		return values
	}
	snapshots := map[string]map[string]uint64{}
	hash := func(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
	read := func(path string) []byte {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	goodControl := read(nd.control)
	goodBundle := read(filepath.Join(nd.bundles, "bundle-1.sbn"))
	type observed struct {
		ID     string `json:"id"`
		Bundle uint64 `json:"bundle"`
	}
	ids := make([]observed, 0, 80)
	phases := map[string]nativeReply{}
	send := func(phase string, version uint64) {
		good := nativeGet(t, client, base, "/query?id=1")
		if good.Status != 200 || good.Action != "allow" || good.Body != "example-origin-reached" {
			t.Fatalf("%s benign: %+v", phase, good)
		}
		for i := 0; i < 20; i++ {
			r := nativeGet(t, client, base, "/query?id="+url.QueryEscape("-1 UNION SELECT 'example-marker'--"))
			if r.Status != 403 || r.Action != "block" || !strings.HasPrefix(r.ID, "STR-") || r.Rules != "700011" {
				t.Fatalf("%s SQLi: %+v", phase, r)
			}
			ids = append(ids, observed{r.ID, version})
			if i == 0 {
				phases[phase] = r
			}
			time.Sleep(20 * time.Millisecond)
		}
		snapshots[phase] = metrics()
	}
	send("before_corruption", 1)
	originalPublish := p.deployer.Publish
	var original []byte
	var expected, corrupt string
	p.deployer.Publish = func(c context.Context, b store.Bundle, a store.Audit) (store.Rollout, error) {
		if b.Version != 2 {
			return store.Rollout{}, fmt.Errorf("expected fault at bundle 2, got %d", b.Version)
		}
		data, err := p.objects.Get(c, b.ObjectKey)
		if err != nil {
			return store.Rollout{}, err
		}
		h, err := bundlefmt.Verify(data, p.pub)
		if err != nil || h.Version != 2 {
			return store.Rollout{}, fmt.Errorf("original bundle 2: %v", err)
		}
		original = append([]byte(nil), data...)
		expected = hash(data)
		if expected != hex.EncodeToString(b.SHA256) {
			return store.Rollout{}, fmt.Errorf("original metadata mismatch")
		}
		data[len(data)-65] ^= 1 // payload byte, leaving size and signature bytes unchanged
		corrupt = hash(data)
		if err = p.objects.Put(c, b.ObjectKey, data, corrupt); err != nil {
			return store.Rollout{}, err
		}
		stored, err := p.objects.Get(c, b.ObjectKey)
		if err != nil || hash(stored) != corrupt {
			return store.Rollout{}, fmt.Errorf("corruption not stored: %v", err)
		}
		return originalPublish(c, b, a)
	}
	r2 := deploy(2, "MODE_SHADOW") // accepting this bad artifact would stop SQLi blocking
	waitFor(t, "corrupt rollout FAILED", 30*time.Second, func() bool { return p.rollout(t, r2).Rollout.State == "FAILED" })
	failed := p.rollout(t, r2).Rollout
	if len(failed.Nodes) != 1 || failed.Nodes[0].State != "FAILED" || !strings.Contains(failed.Nodes[0].Error, "sha256 does not match") {
		t.Fatalf("wrong failure: %+v", failed)
	}
	if expected == corrupt || len(original) == 0 || !strings.Contains(nd.proc.logBuf.String(), "sha256 does not match") {
		t.Fatal("corruption was not rejected by real agent")
	}
	if nd.controlVersion() != 1 || hash(read(nd.control)) != hash(goodControl) || hash(read(filepath.Join(nd.bundles, "bundle-1.sbn"))) != hash(goodBundle) {
		t.Fatal("last-known-good changed after corrupt artifact")
	}
	for _, name := range []string{"bundle-2.sbn", ".partial-2"} {
		if _, err := os.Stat(filepath.Join(nd.bundles, name)); !os.IsNotExist(err) {
			t.Fatalf("rejected artifact retained: %s %v", name, err)
		}
	}
	send("after_rejection", 1)
	// Repair the owned source object so the next replay can verify its exact
	// baseline. Repair alone does not resume the failed rollout.
	p.deployer.Publish = originalPublish
	if err := p.objects.Put(ctx, "bundles/00000000000000000002/bundle-2.sbn", original, expected); err != nil {
		t.Fatal(err)
	}
	if _, err := bundlefmt.Verify(read(filepath.Join(nd.bundles, "bundle-1.sbn")), p.pub); err != nil {
		t.Fatal(err)
	}
	send("after_storage_repair", 1)
	if nd.controlVersion() != 1 || p.rollout(t, r2).Rollout.State != "FAILED" {
		t.Fatal("repair resumed failed rollout")
	}
	fallbackBefore := strings.Count(nd.proc.logBuf.String(), "no worker metrics")
	r3 := deploy(3, "MODE_ENFORCE")
	waitFor(t, "new approved rollout 3 DONE", 30*time.Second, func() bool { return p.rollout(t, r3).Rollout.State == "DONE" })
	if nd.controlVersion() != 3 || strings.Count(nd.proc.logBuf.String(), "no worker metrics") != fallbackBefore {
		t.Fatal("recovery lacks real worker ACK")
	}
	installed := read(filepath.Join(nd.bundles, "bundle-3.sbn"))
	if h, err := bundlefmt.Verify(installed, p.pub); err != nil || h.Version != 3 {
		t.Fatalf("recovered signature: %+v %v", h, err)
	}
	send("after_explicit_recovery", 3)
	waitFor(t, "all native events durable", 30*time.Second, func() bool {
		var n uint64
		if err := p.events.Conn().QueryRow(ctx, "SELECT count() FROM events FINAL WHERE node_id=?", nd.id).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n == uint64(len(ids)) && metrics()["strata_agent_spool_unacked_batches"] == 0
	})
	finalMetrics := metrics()
	if finalMetrics["strata_agent_acked_seq"] == 0 || finalMetrics["strata_agent_acked_seq"] != finalMetrics["strata_agent_spool_last_seq"] || finalMetrics["strata_agent_bundle_active_version"] != 3 {
		t.Fatal("recovery ACK or active bundle:", finalMetrics)
	}
	for _, key := range []string{"strata_agent_events_invalid_total", "strata_agent_events_truncated_total", "strata_agent_spool_dropped_events_total"} {
		if finalMetrics[key] != 0 {
			t.Fatal("agent error:", key, finalMetrics[key])
		}
	}
	for _, phase := range []string{"after_rejection", "after_storage_repair"} {
		if snapshots[phase]["strata_agent_bundle_active_version"] != 1 {
			t.Fatal("bad bundle activated:", phase, snapshots[phase])
		}
	}
	unique := map[string]bool{}
	for _, o := range ids {
		if unique[o.ID] {
			t.Fatal("duplicate native ID:", o.ID)
		}
		unique[o.ID] = true
		event, err := p.events.GetEvent(ctx, o.ID)
		if err != nil || event.NodeID != nd.id || event.PolicyVersion != o.Bundle || event.Action != "block" || len(event.MatchedRules) != 1 || event.MatchedRules[0] != 700011 {
			t.Fatalf("wrong persisted native event: %+v %v", event, err)
		}
	}
	// Report only bundle status, never tokens, enrollment data or private keys.
	agentLog := nd.proc.logBuf.String()
	var statuses []string
	for _, line := range strings.Split(agentLog, "\n") {
		if strings.Contains(line, " bundle version=") || strings.Contains(line, " fetching bundle version=") {
			statuses = append(statuses, line)
		}
	}
	if len(statuses) < 8 {
		t.Fatal("missing bundle status evidence")
	}
	if err := os.WriteFile(filepath.Join(output, "agent-bundle-status.log"), []byte(strings.Join(statuses, "\n")+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	hashes := map[string]string{}
	for label, file := range map[string]string{"agent": bin, "compiler": compiler, "replay": replayBin, "nginx": nginx, "module": module} {
		hashes[label] = hash(read(file))
	}
	for _, pattern := range []string{"asan.*", "ubsan.*"} {
		reports, err := filepath.Glob(filepath.Join(output, pattern))
		if err != nil || len(reports) != 0 {
			t.Fatalf("sanitizer reports: %v %v", reports, err)
		}
	}
	result := map[string]any{"fault": "private MinIO payload changed after verified deployment, before real Fleet notification", "expected_sha256": expected, "corrupted_sha256": corrupt, "bundle_bytes": len(original), "failed_rollout": failed, "last_known_good_control_sha256": hash(goodControl), "last_known_good_bundle_sha256": hash(goodBundle), "http_phases": phases, "native_events": ids, "persisted_native_ids": len(ids), "agent_metrics": snapshots, "final_agent_metrics": finalMetrics, "recovery_rollout": p.rollout(t, r3).Rollout, "recovery_bundle_sha256": hash(installed), "recovery_missing_metrics_fallback": false, "binary_sha256": hashes, "scope": "single node, two synthetic rules; real replay/approval/MinIO/Fleet/agent/NGINX/socket/CH; in-process CP services, serial requests, not full operational game day"}
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(output, "result.json"), append(data, '\n'), 0644); err != nil {
		t.Fatal(err)
	}
	t.Logf("PASS corrupted artifact rejected, LKG HTTP blocking preserved, explicit replay/approval/deploy recovered; %d/%d native IDs persisted", len(unique), len(ids))
}
