package standalone

import (
	"context"
	eventv1 "github.com/strata/strata/agent/gen/strata/event/v1"
	"google.golang.org/protobuf/proto"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStandaloneRunnerEndToEnd(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "events.sock")
	controlFile := filepath.Join(tmpDir, "control")
	bundleDir := filepath.Join(tmpDir, "bundles")
	jsonlPath := filepath.Join(tmpDir, "events.jsonl")

	bundleBytes, pub, _ := makeTestBundle(100, 0xAA)
	pubFile := filepath.Join(tmpDir, "bundle.pub")
	if err := os.WriteFile(pubFile, pub, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(bundleDir, 0o755); err != nil {
		t.Fatal(err)
	}
	bundleFile := filepath.Join(bundleDir, "bundle.sbn")
	if err := os.WriteFile(bundleFile, bundleBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := Config{
		Standalone:         true,
		NodeID:             "example-node",
		BundlePubKey:       pubFile,
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
		NodeId:   "untrusted-worker-id",
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
		if strings.Contains(string(b), "STR-E2E-TEST-0001") && strings.Contains(string(b), `"node_id":"example-node"`) {
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
