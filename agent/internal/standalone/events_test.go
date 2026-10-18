package standalone

import (
	"encoding/json"
	eventv1 "github.com/strata/strata/agent/gen/strata/event/v1"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

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
		ClientIp: "192.0.2.1",
		Method:   "POST",
		Host:     "api.example.test",
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
	if m["client_ip"] != "192.0.2.1" {
		t.Errorf("expected client_ip 192.0.2.1, got %v", m["client_ip"])
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
