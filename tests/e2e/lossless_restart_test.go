package e2e

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	eventv1 "github.com/strata/strata/agent/gen/strata/event/v1"
	"github.com/strata/strata/control-plane/ingest"
)

// losslessWorker pumps events over Unix datagram socket with automatic retry.
type losslessWorker struct {
	socketPath string
	localPath  string
	conn       *net.UnixConn
	mu         sync.Mutex
}

func newLosslessWorker(socketPath string) (*losslessWorker, error) {
	localPath := filepath.Join(os.TempDir(), fmt.Sprintf("lossless-worker-%d-%d.sock", os.Getpid(), time.Now().UnixNano()))
	c, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: localPath, Net: "unixgram"})
	if err != nil {
		return nil, fmt.Errorf("listen unixgram: %w", err)
	}
	return &losslessWorker{
		socketPath: socketPath,
		localPath:  localPath,
		conn:       c,
	}, nil
}

func (w *losslessWorker) send(ev *eventv1.Event) error {
	b, err := proto.Marshal(ev)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}

	addr := &net.UnixAddr{Name: w.socketPath, Net: "unixgram"}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		_, err := w.conn.WriteTo(b, addr)
		if err == nil {
			return nil
		}
		time.Sleep(5 * time.Millisecond)
	}
	return fmt.Errorf("timeout sending event %s to socket %s", ev.GetBlockId(), w.socketPath)
}

func (w *losslessWorker) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.conn != nil {
		err := w.conn.Close()
		w.conn = nil
		_ = os.Remove(w.localPath)
		return err
	}
	return nil
}

func isClickHouseReady(httpAddr, password string) bool {
	client := http.Client{Timeout: 800 * time.Millisecond}
	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s/?query=SELECT+1", httpAddr), nil)
	if err != nil {
		return false
	}
	if password != "" {
		req.SetBasicAuth("default", password)
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func ensureClickHouse(t *testing.T) string {
	t.Helper()
	nativeAddr := os.Getenv("CLICKHOUSE_ADDR")
	if nativeAddr == "" {
		nativeAddr = "127.0.0.1:9000"
	}
	httpAddr := os.Getenv("CLICKHOUSE_HTTP_ADDR")
	if httpAddr == "" {
		httpAddr = "127.0.0.1:8123"
	}
	password := os.Getenv("CLICKHOUSE_PASSWORD")
	if password == "" {
		password = "strata"
	}

	if isClickHouseReady(httpAddr, password) {
		t.Logf("ClickHouse is already running at %s (native: %s)", httpAddr, nativeAddr)
		return nativeAddr
	}

	containerName := fmt.Sprintf("strata-e2e-ch-%d", time.Now().UnixNano()%100000)
	t.Logf("Starting temporary ClickHouse container %s...", containerName)

	cmd := exec.Command("docker", "run", "-d", "--rm",
		"--name", containerName,
		"-p", "9000:9000",
		"-p", "8123:8123",
		"-e", fmt.Sprintf("CLICKHOUSE_PASSWORD=%s", password),
		"--ulimit", "nofile=262144:262144",
		"clickhouse/clickhouse-server:latest",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to start ClickHouse container: %v, output: %s", err, string(out))
	}

	t.Cleanup(func() {
		t.Logf("Stopping ClickHouse container %s...", containerName)
		_ = exec.Command("docker", "stop", "-t", "2", containerName).Run()
	})

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if isClickHouseReady(httpAddr, password) {
			t.Logf("ClickHouse container %s is ready at %s", containerName, nativeAddr)
			return nativeAddr
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for ClickHouse to start at %s", httpAddr)
	return nativeAddr
}

type agentProcess struct {
	cmd    *exec.Cmd
	logBuf *bytes.Buffer
	done   chan error
}

func buildAgentBinary(t *testing.T) string {
	t.Helper()
	binPath := filepath.Join(t.TempDir(), "strata-agent")
	absBinPath, err := filepath.Abs(binPath)
	if err != nil {
		t.Fatalf("abs path: %v", err)
	}
	cmd := exec.Command("go", "build", "-o", absBinPath, "./cmd/strata-agent")
	cmd.Dir = filepath.Join("..", "..", "agent")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to build strata-agent: %v\nOutput: %s", err, string(out))
	}
	return absBinPath
}

func startAgentProcess(t *testing.T, binPath string, args ...string) *agentProcess {
	t.Helper()
	buf := new(bytes.Buffer)
	cmd := exec.Command(binPath, args...)
	cmd.Stdout = buf
	cmd.Stderr = buf

	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start strata-agent process: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	return &agentProcess{
		cmd:    cmd,
		logBuf: buf,
		done:   done,
	}
}

func (p *agentProcess) stop(timeout time.Duration) error {
	if p.cmd.Process == nil {
		return nil
	}
	_ = p.cmd.Process.Signal(syscall.SIGTERM)

	select {
	case err := <-p.done:
		if err != nil && err.Error() != "signal: terminated" && err.Error() != "exit status 0" {
			return err
		}
		return nil
	case <-time.After(timeout):
		_ = p.cmd.Process.Kill()
		return fmt.Errorf("agent process timed out after %v: logs: %s", timeout, p.logBuf.String())
	}
}

// waitForSocket polls until the Unix socket exists and can be dialed.
func waitForSocket(sockPath string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fi, err := os.Stat(sockPath); err == nil && fi.Mode()&os.ModeSocket != 0 {
			conn, dialErr := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: sockPath, Net: "unixgram"})
			if dialErr == nil {
				_ = conn.Close()
				return nil
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for socket %s", sockPath)
}

// TestLosslessRestartUnderLoad verifies W06-Q-01: restarting strata-agent under continuous load
// guarantees 0 event loss and 0 duplicate events in ClickHouse.
func TestLosslessRestartUnderLoad(t *testing.T) {
	chAddr := ensureClickHouse(t)

	password := os.Getenv("CLICKHOUSE_PASSWORD")
	if password == "" {
		password = "strata"
	}

	ctx := context.Background()
	store, err := ingest.NewClickHouseStore(ctx, ingest.ClickHouseConfig{
		Addr:     chAddr,
		Database: "default",
		Username: "default",
		Password: password,
		Table:    "events",
	})
	if err != nil {
		t.Fatalf("connect to clickhouse: %v", err)
	}
	defer store.Close()

	// Ensure schema exists and clean previous test records
	schemaSQLPath := filepath.Join("..", "..", "control-plane", "ingest", "schema.sql")
	schemaBytes, err := os.ReadFile(schemaSQLPath)
	if err != nil {
		t.Fatalf("read schema.sql: %v", err)
	}
	// ClickHouse takes one statement per query.
	for _, stmt := range strings.Split(string(schemaBytes), ";") {
		if strings.TrimSpace(stmt) == "" {
			continue
		}
		if err := store.Conn().Exec(ctx, stmt); err != nil {
			t.Fatalf("execute schema.sql: %v", err)
		}
	}
	// node_seq too: a watermark left by an earlier run would drop this run's batches.
	for _, table := range []string{"events", "node_seq"} {
		if err := store.Conn().Exec(ctx, "TRUNCATE TABLE IF EXISTS "+table); err != nil {
			t.Fatalf("truncate %s: %v", table, err)
		}
	}

	// Set up IngestService with short flush interval
	batcherCfg := ingest.BatcherConfig{
		MaxBatchSize:  100,
		FlushInterval: 25 * time.Millisecond,
		BufferSize:    20000,
	}
	ingestSvc := ingest.NewIngestService(store, batcherCfg, 1*time.Hour)
	defer ingestSvc.Close(ctx)

	// Start FleetIngestServer with mTLS
	certsDir := t.TempDir()
	srv, certs, err := StartFleetIngestServer(certsDir, ingestSvc, store)
	if err != nil {
		t.Fatalf("start fleet ingest server: %v", err)
	}
	defer srv.Stop()

	// Build strata-agent binary
	t.Log("Building strata-agent binary...")
	agentBin := buildAgentBinary(t)

	// Set up persistent agent directories
	baseDir := t.TempDir()
	spoolDir := filepath.Join(baseDir, "spool")
	sockPath := filepath.Join(baseDir, "events.sock")

	agentArgs := []string{
		"-event-socket", sockPath,
		"-spool-dir", spoolDir,
		"-spool-max-bytes", "2147483648",
		"-server", srv.Addr(),
		"-server-name", "cp.example.test",
		"-tls-ca", certs.CA,
		"-tls-cert", certs.ClientCert,
		"-tls-key", certs.ClientKey,
		"-node-id", "node-lossless-1",
	}

	const (
		totalEvents  = 2000
		restartAfter = 800 // Trigger agent restart after sending 800 events
	)

	t.Logf("1. Starting strata-agent process 1 on socket %s...", sockPath)
	p1 := startAgentProcess(t, agentBin, agentArgs...)

	// Wait for socket to be ready
	if err := waitForSocket(sockPath, 5*time.Second); err != nil {
		t.Fatalf("agent socket not ready: %v, logs: %s", err, p1.logBuf.String())
	}

	worker, err := newLosslessWorker(sockPath)
	if err != nil {
		t.Fatalf("create worker: %v", err)
	}
	defer worker.Close()

	var (
		eventsSent   atomic.Uint64
		restartDone  = make(chan struct{})
		sendDone     = make(chan struct{})
		workerErrors = make(chan error, totalEvents)
	)

	t.Logf("2. Streaming %d events under continuous load...", totalEvents)
	start := time.Now()

	// Worker goroutine: pumps events with target rate ~1000 eps
	go func() {
		defer close(sendDone)
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()

		for i := 0; i < totalEvents; i++ {
			<-ticker.C
			blockID := fmt.Sprintf("STR-Q001-0000-0000-%04X", i)

			ev := &eventv1.Event{
				BlockId:       blockID,
				TimeUnixMs:    uint64(time.Now().UnixMilli()),
				NodeId:        "node-lossless-1",
				RequestId:     fmt.Sprintf("req-%06d", i),
				PolicyId:      "policy-e2e",
				BundleVersion: 1,
				ClientIp:      fmt.Sprintf("198.51.100.%d", (i%250)+1),
				Identity:      "test-client",
				Method:        "POST",
				Host:          "api.example.test",
				Path:          fmt.Sprintf("/v1/resource/%d", i),
				Status:        403,
				Action:        eventv1.Action_ACTION_BLOCK,
				LayerScores: map[string]int32{
					"protocol": 10,
					"sqli":     25,
					"xss":      0,
					"anomaly":  35,
				},
				RuleIds: []uint32{942100, 942110},
				Matches: []*eventv1.Match{
					{
						RuleId:  942100,
						Layer:   "sqli",
						Field:   "ARGS:id",
						Snippet: []byte("1' OR '1'='1"),
					},
				},
			}

			if err := worker.send(ev); err != nil {
				workerErrors <- err
				return
			}
			eventsSent.Add(1)

			// Signal restart once threshold is reached
			if i+1 == restartAfter {
				close(restartDone)
			}
		}
	}()

	// Wait until threshold is reached, then perform restart
	<-restartDone
	t.Logf("3. Load reached %d events. Terminating agent 1 via SIGTERM while load continues...", restartAfter)

	restartStart := time.Now()
	if err := p1.stop(5 * time.Second); err != nil {
		t.Fatalf("agent 1 stop: %v, logs: %s", err, p1.logBuf.String())
	}
	t.Logf("Agent 1 cleanly stopped in %v. Launching agent 2 on SAME spool: %s...", time.Since(restartStart), spoolDir)

	// Start Agent 2 with identical configuration and spool directory
	p2 := startAgentProcess(t, agentBin, agentArgs...)
	defer func() {
		_ = p2.stop(5 * time.Second)
	}()

	// Wait for worker to finish sending all 2000 events
	select {
	case <-sendDone:
		t.Logf("Worker completed sending %d events in %v", eventsSent.Load(), time.Since(start))
	case err := <-workerErrors:
		t.Fatalf("worker error: %v", err)
	case <-time.After(30 * time.Second):
		t.Fatalf("timeout waiting for worker to finish sending events")
	}

	if sent := eventsSent.Load(); sent != totalEvents {
		t.Fatalf("worker sent %d events; expected %d", sent, totalEvents)
	}

	entries, _ := os.ReadDir(spoolDir)
	t.Logf("Spool directory %s has %d files", spoolDir, len(entries))
	for _, e := range entries {
		fi, _ := e.Info()
		t.Logf("  Spool file: %s (size: %d bytes)", e.Name(), fi.Size())
	}
	t.Logf("Server batches received: %d, accepted: %d", srv.receivedBatches.Load(), srv.acceptedBatches.Load())

	t.Log("4. Waiting for agent 2 to push all events to control plane and ClickHouse...")
	deadline := time.Now().Add(20 * time.Second)
	var finalCount uint64

	for time.Now().Before(deadline) {
		// Flush ingest service buffer
		flushCtx, flushCancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = ingestSvc.Flush(flushCtx)
		flushCancel()

		var count uint64
		err := store.Conn().QueryRow(ctx, "SELECT count() FROM events WHERE block_id LIKE 'STR-Q001-%'").Scan(&count)
		if err == nil {
			finalCount = count
			if count == totalEvents {
				t.Logf("All %d events confirmed in ClickHouse!", count)
				break
			}
		}
		time.Sleep(200 * time.Millisecond)
	}

	// Stop agent 2 cleanly
	if err := p2.stop(5 * time.Second); err != nil {
		t.Logf("agent 2 stop: %v, logs: %s", err, p2.logBuf.String())
	}

	// Final flush of IngestService
	flushCtx, flushCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer flushCancel()
	_ = ingestSvc.Flush(flushCtx)

	t.Log("5. Verifying ClickHouse records: 0 event loss, 0 duplicates...")

	// Verify Total Event Count
	err = store.Conn().QueryRow(ctx, "SELECT count() FROM events WHERE block_id LIKE 'STR-Q001-%'").Scan(&finalCount)
	if err != nil {
		t.Fatalf("query event count: %v", err)
	}

	t.Logf("ClickHouse received %d / %d events", finalCount, totalEvents)
	if finalCount != totalEvents {
		t.Fatalf("EVENT LOSS DETECTED! Sent: %d, Received in ClickHouse: %d (Loss: %d)\nAgent 1 logs:\n%s\nAgent 2 logs:\n%s",
			totalEvents, finalCount, totalEvents-finalCount, p1.logBuf.String(), p2.logBuf.String())
	}

	// Verify Duplicate Count
	var duplicateCount uint64
	dupQuery := `
		SELECT count() FROM (
			SELECT block_id, count() AS c 
			FROM events 
			WHERE block_id LIKE 'STR-Q001-%' 
			GROUP BY block_id 
			HAVING c > 1
		)`
	err = store.Conn().QueryRow(ctx, dupQuery).Scan(&duplicateCount)
	if err != nil {
		t.Fatalf("query duplicates: %v", err)
	}

	if duplicateCount != 0 {
		t.Fatalf("DUPLICATE EVENTS DETECTED! %d block_ids were recorded more than once", duplicateCount)
	}

	// Spot-check individual records (boundary, restart boundary, final)
	spotCheckIDs := []string{
		"STR-Q001-0000-0000-0000",
		fmt.Sprintf("STR-Q001-0000-0000-%04X", restartAfter-1),
		fmt.Sprintf("STR-Q001-0000-0000-%04X", restartAfter),
		fmt.Sprintf("STR-Q001-0000-0000-%04X", totalEvents-1),
	}

	for _, blockID := range spotCheckIDs {
		ev, err := store.GetEvent(ctx, blockID)
		if err != nil {
			t.Fatalf("lookup %s failed: %v", blockID, err)
		}
		if ev.BlockID != blockID {
			t.Fatalf("expected BlockID %s, got %s", blockID, ev.BlockID)
		}
		if ev.Action != "block" {
			t.Fatalf("event %s expected action 'block', got '%s'", blockID, ev.Action)
		}
		if ev.ScoreAnomaly != 35 {
			t.Fatalf("event %s expected anomaly score 35, got %d", blockID, ev.ScoreAnomaly)
		}
		if len(ev.Violations) == 0 || ev.Violations[0].RuleID != 942100 {
			t.Fatalf("event %s missing violation 942100", blockID)
		}
	}

	t.Logf("SUCCESS: All %d events accounted for in ClickHouse with zero loss and zero duplicates across agent restart under load!", totalEvents)
}
