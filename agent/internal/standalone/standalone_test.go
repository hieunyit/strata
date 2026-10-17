package standalone

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	eventv1 "github.com/strata/strata/agent/gen/strata/event/v1"
	"github.com/strata/strata/agent/internal/bundles"
	"google.golang.org/protobuf/proto"
)

func makeTestBundleWithKey(version uint64, seed byte, priv ed25519.PrivateKey) []byte {
	data := make([]byte, 128)
	copy(data[:8], "STRBNDL\x00")
	binary.LittleEndian.PutUint16(data[8:], 1) // format = 1
	binary.LittleEndian.PutUint16(data[10:], 0)
	binary.LittleEndian.PutUint32(data[12:], 1) // 1 policy
	binary.LittleEndian.PutUint64(data[16:], version)
	binary.LittleEndian.PutUint64(data[24:], 1000)
	for i := 32; i < 64; i++ {
		data[i] = seed
	}

	body := data[:64]
	sig := ed25519.Sign(priv, body)
	return append(body, sig...)
}

func makeTestBundle(version uint64, seed byte) ([]byte, ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(err)
	}
	return makeTestBundleWithKey(version, seed, priv), pub, priv
}

func TestEventExporterJSONLAndSyslog(t *testing.T) {
	tmpDir := t.TempDir()
	jsonlPath := filepath.Join(tmpDir, "events.jsonl")

	// Start a mock UDP Syslog listener
	syslogAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve udp: %v", err)
	}
	syslogConn, err := net.ListenUDP("udp", syslogAddr)
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer syslogConn.Close()

	exp, err := NewEventExporter(jsonlPath, syslogConn.LocalAddr().String(), "strata-test")
	if err != nil {
		t.Fatalf("NewEventExporter: %v", err)
	}
	defer exp.Close()

	testEvt := &eventv1.Event{
		BlockId:  "STR-TEST-1234-5678-ABCD",
		ClientIp: "1.2.3.4",
		Method:   "POST",
		Host:     "example.com",
		Path:     "/login",
		RuleIds:  []uint32{942100},
	}

	if err := exp.Export(testEvt); err != nil {
		t.Fatalf("Export error: %v", err)
	}

	// 1. Verify JSON Lines file
	content, err := os.ReadFile(jsonlPath)
	if err != nil {
		t.Fatalf("ReadFile jsonl: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected 1 line, got %d", len(lines))
	}

	var m map[string]interface{}
	if err := json.Unmarshal([]byte(lines[0]), &m); err != nil {
		t.Fatalf("unmarshal json line: %v", err)
	}
	if m["block_id"] != "STR-TEST-1234-5678-ABCD" {
		t.Errorf("expected block_id STR-TEST-1234-5678-ABCD, got %v", m["block_id"])
	}
	if m["client_ip"] != "1.2.3.4" {
		t.Errorf("expected client_ip 1.2.3.4, got %v", m["client_ip"])
	}

	// 2. Verify Syslog message
	buf := make([]byte, 2048)
	_ = syslogConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := syslogConn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("syslog read: %v", err)
	}
	syslogMsg := string(buf[:n])
	if !strings.Contains(syslogMsg, "strata-test") || !strings.Contains(syslogMsg, "STR-TEST-1234-5678-ABCD") {
		t.Errorf("syslog message missing tag or event_id: %s", syslogMsg)
	}

	exported, dropped := exp.Stats()
	if exported != 1 || dropped != 0 {
		t.Errorf("stats: exported=%d, dropped=%d", exported, dropped)
	}
}

func TestBundleWatcherSyncAndHotReload(t *testing.T) {
	tmpDir := t.TempDir()
	bundleDir := filepath.Join(tmpDir, "bundles")
	controlFile := filepath.Join(tmpDir, "control")
	pubKeyFile := filepath.Join(tmpDir, "bundle.pub")

	bundleBytes1, pubKey, privKey := makeTestBundle(1, 0x11)
	if err := os.WriteFile(pubKeyFile, pubKey, 0o644); err != nil {
		t.Fatal(err)
	}

	bundlePath1 := filepath.Join(bundleDir, "bundle-1.sbn")
	if err := os.MkdirAll(bundleDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bundlePath1, bundleBytes1, 0o644); err != nil {
		t.Fatal(err)
	}

	watcher, err := NewBundleWatcher("", bundleDir, "", controlFile, pubKeyFile, 50*time.Millisecond)
	if err != nil {
		t.Fatalf("NewBundleWatcher: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Initial Sync
	updated, err := watcher.SyncOnce(ctx)
	if err != nil {
		t.Fatalf("SyncOnce initial: %v", err)
	}
	if !updated {
		t.Fatalf("expected initial sync to update control file")
	}

	// Verify Control File
	ctl, err := bundles.ReadControl(controlFile)
	if err != nil {
		t.Fatalf("ReadControl: %v", err)
	}
	if ctl.Version != 1 {
		t.Errorf("expected version 1, got %d", ctl.Version)
	}
	if ctl.Name != "bundle-1.sbn" {
		t.Errorf("expected name bundle-1.sbn, got %s", ctl.Name)
	}

	// Re-sync without changes should report updated = false
	updated2, err := watcher.SyncOnce(ctx)
	if err != nil || updated2 {
		t.Errorf("re-sync without changes updated=%v err=%v", updated2, err)
	}

	// Hot reload with newer bundle (version 2) signed with same private key
	time.Sleep(10 * time.Millisecond) // ensure newer mod time
	bundleBytes2 := makeTestBundleWithKey(2, 0x22, privKey)
	bundlePath2 := filepath.Join(bundleDir, "bundle-2.sbn")
	if err := os.WriteFile(bundlePath2, bundleBytes2, 0o644); err != nil {
		t.Fatal(err)
	}

	updated3, err := watcher.SyncOnce(ctx)
	if err != nil {
		t.Fatalf("SyncOnce version 2: %v", err)
	}
	if !updated3 {
		t.Fatalf("expected sync to detect bundle-2.sbn update")
	}

	ctl2, err := bundles.ReadControl(controlFile)
	if err != nil {
		t.Fatalf("ReadControl 2: %v", err)
	}
	if ctl2.Version != 2 {
		t.Errorf("expected version 2, got %d", ctl2.Version)
	}
	if ctl2.Name != "bundle-2.sbn" {
		t.Errorf("expected name bundle-2.sbn, got %s", ctl2.Name)
	}
}

func TestStandaloneRunnerEndToEnd(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "events.sock")
	controlFile := filepath.Join(tmpDir, "control")
	bundleDir := filepath.Join(tmpDir, "bundles")
	jsonlPath := filepath.Join(tmpDir, "events.jsonl")

	bundleBytes, _, _ := makeTestBundle(100, 0xAA)
	if err := os.MkdirAll(bundleDir, 0o755); err != nil {
		t.Fatal(err)
	}
	bundleFile := filepath.Join(bundleDir, "bundle.sbn")
	if err := os.WriteFile(bundleFile, bundleBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := Config{
		Standalone:         true,
		EventSocket:        sockPath,
		ControlFile:        controlFile,
		BundleFile:         bundleFile,
		BundleDir:          bundleDir,
		BundlePollInterval: 100 * time.Millisecond,
		EventsJSONL:        jsonlPath,
		MetricsAddr:        "",
	}

	runner, err := New(cfg)
	if err != nil {
		t.Fatalf("New runner: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runErr := make(chan error, 1)
	go func() {
		runErr <- runner.Run(ctx)
	}()

	// Wait for socket to become available
	var clientConn *net.UnixConn
	for i := 0; i < 20; i++ {
		time.Sleep(50 * time.Millisecond)
		conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: sockPath, Net: "unixgram"})
		if err == nil {
			clientConn = conn
			break
		}
	}
	if clientConn == nil {
		t.Fatal("could not connect to event socket")
	}
	defer clientConn.Close()

	// Send an encoded event
	ev := &eventv1.Event{
		BlockId:  "STR-E2E-TEST-0001",
		ClientIp: "10.0.0.99",
		Method:   "GET",
		Path:     "/api/data",
		Action:   eventv1.Action_ACTION_BLOCK,
	}
	evBytes, _ := proto.Marshal(ev)
	if _, err := clientConn.Write(evBytes); err != nil {
		t.Fatalf("write event to socket: %v", err)
	}

	// Verify events.jsonl has the event
	var matched bool
	for i := 0; i < 20; i++ {
		time.Sleep(50 * time.Millisecond)
		b, _ := os.ReadFile(jsonlPath)
		if strings.Contains(string(b), "STR-E2E-TEST-0001") {
			matched = true
			break
		}
	}
	if !matched {
		t.Fatal("event did not appear in events.jsonl")
	}

	// Cancel and check clean shutdown
	cancel()
	select {
	case err := <-runErr:
		if err != nil && err != context.Canceled {
			t.Fatalf("runner returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("runner did not exit in time")
	}
}
