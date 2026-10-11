package eventsock

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	eventv1 "github.com/strata/strata/agent/gen/strata/event/v1"
)

func readGolden(t *testing.T, name string) []byte {
	t.Helper()
	// Locate engine/tests/golden/events relative to agent/internal/eventsock
	path := filepath.Join("..", "..", "..", "engine", "tests", "golden", "events", name+".bin")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s: %v", path, err)
	}
	return b
}

func TestGoldenEvents(t *testing.T) {
	tests := []struct {
		name     string
		validate func(t *testing.T, ev *eventv1.Event)
	}{
		{
			name: "blocked",
			validate: func(t *testing.T, ev *eventv1.Event) {
				if !strings.HasPrefix(ev.GetBlockId(), "STR-") {
					t.Fatalf("expected STR- prefix, got %q", ev.GetBlockId())
				}
				if ev.GetAction() != eventv1.Action_ACTION_BLOCK {
					t.Fatalf("expected ACTION_BLOCK, got %v", ev.GetAction())
				}
				if ev.GetNodeId() != "node-01" {
					t.Fatalf("expected node-01, got %q", ev.GetNodeId())
				}
				if ev.GetPolicyId() != "example-api" {
					t.Fatalf("expected example-api, got %q", ev.GetPolicyId())
				}
				if ev.GetIdentity() != "user:alice" {
					t.Fatalf("expected user:alice, got %q", ev.GetIdentity())
				}
				if ev.GetRequestId() != "req-12345" {
					t.Fatalf("expected req-12345, got %q", ev.GetRequestId())
				}
				if ev.GetClientIp() != "192.0.2.1" {
					t.Fatalf("expected 192.0.2.1, got %q", ev.GetClientIp())
				}
				if ev.GetHost() != "api.example.test" {
					t.Fatalf("expected api.example.test, got %q", ev.GetHost())
				}
				if ev.GetMethod() != "GET" {
					t.Fatalf("expected GET, got %q", ev.GetMethod())
				}
				if ev.GetPath() != "/test" {
					t.Fatalf("expected /test, got %q", ev.GetPath())
				}
				if ev.GetStatus() != 403 {
					t.Fatalf("expected 403, got %d", ev.GetStatus())
				}
				if len(ev.GetRuleIds()) == 0 {
					t.Fatalf("expected rule IDs, got none")
				}
				if len(ev.GetMatches()) == 0 {
					t.Fatalf("expected matches, got none")
				}
				m := ev.GetMatches()[0]
				if m.GetRuleId() != 899001 {
					t.Fatalf("expected rule 899001, got %d", m.GetRuleId())
				}
				if !strings.Contains(string(m.GetSnippet()), "STRATA-TEST-BLOCK") {
					t.Fatalf("expected snippet with STRATA-TEST-BLOCK, got %q", string(m.GetSnippet()))
				}
				if ev.GetLayerScores()["anomaly"] != 100 {
					t.Fatalf("expected anomaly score 100, got %d", ev.GetLayerScores()["anomaly"])
				}
			},
		},
		{
			name: "shadow",
			validate: func(t *testing.T, ev *eventv1.Event) {
				if !strings.HasPrefix(ev.GetBlockId(), "EVT-") {
					t.Fatalf("expected EVT- prefix, got %q", ev.GetBlockId())
				}
				if ev.GetAction() != eventv1.Action_ACTION_LOG {
					t.Fatalf("expected ACTION_LOG, got %v", ev.GetAction())
				}
				if ev.GetNodeId() != "node-shadow" {
					t.Fatalf("expected node-shadow, got %q", ev.GetNodeId())
				}
				if ev.GetIdentity() != "user:bob" {
					t.Fatalf("expected user:bob, got %q", ev.GetIdentity())
				}
				if ev.GetRequestId() != "req-shadow-99" {
					t.Fatalf("expected req-shadow-99, got %q", ev.GetRequestId())
				}
				if ev.GetClientIp() != "192.0.2.2" {
					t.Fatalf("expected 192.0.2.2, got %q", ev.GetClientIp())
				}
				if ev.GetHost() != "shadow.example.test" {
					t.Fatalf("expected shadow.example.test, got %q", ev.GetHost())
				}
				if ev.GetStatus() != 0 {
					t.Fatalf("expected 0, got %d", ev.GetStatus())
				}
			},
		},
		{
			name: "engine_error",
			validate: func(t *testing.T, ev *eventv1.Event) {
				if !strings.HasPrefix(ev.GetBlockId(), "EVT-") {
					t.Fatalf("expected EVT- prefix, got %q", ev.GetBlockId())
				}
				if ev.GetAction() != eventv1.Action_ACTION_LOG {
					t.Fatalf("expected ACTION_LOG, got %v", ev.GetAction())
				}
				if ev.GetNodeId() != "node-err" {
					t.Fatalf("expected node-err, got %q", ev.GetNodeId())
				}
				if ev.GetRequestId() != "req-err-1" {
					t.Fatalf("expected req-err-1, got %q", ev.GetRequestId())
				}
				if ev.GetClientIp() != "192.0.2.3" {
					t.Fatalf("expected 192.0.2.3, got %q", ev.GetClientIp())
				}
				if ev.GetStatus() != 500 {
					t.Fatalf("expected 500, got %d", ev.GetStatus())
				}
			},
		},
		{
			name: "long_snippet",
			validate: func(t *testing.T, ev *eventv1.Event) {
				if !strings.HasPrefix(ev.GetBlockId(), "STR-") {
					t.Fatalf("expected STR- prefix, got %q", ev.GetBlockId())
				}
				if ev.GetAction() != eventv1.Action_ACTION_BLOCK {
					t.Fatalf("expected ACTION_BLOCK, got %v", ev.GetAction())
				}
				if ev.GetHost() != "snip.example.test" {
					t.Fatalf("expected snip.example.test, got %q", ev.GetHost())
				}
				// Verify CCCD masking: 079099001122 -> ************
				foundMasked := false
				for _, m := range ev.GetMatches() {
					s := string(m.GetSnippet())
					if strings.Contains(s, "************") {
						foundMasked = true
					}
					if strings.Contains(s, "079099001122") {
						t.Fatalf("unmasked CCCD found in snippet: %q", s)
					}
				}
				if !foundMasked {
					t.Fatalf("expected masked CCCD in snippet, matches=%+v", ev.GetMatches())
				}
			},
		},
		{
			name: "large_event_truncated",
			validate: func(t *testing.T, ev *eventv1.Event) {
				if !strings.HasPrefix(ev.GetBlockId(), "STR-") {
					t.Fatalf("expected STR- prefix, got %q", ev.GetBlockId())
				}
				if ev.GetNodeId() != "node-huge" {
					t.Fatalf("expected node-huge, got %q", ev.GetNodeId())
				}
				if ev.GetPolicyId() != "example-huge" {
					t.Fatalf("expected example-huge, got %q", ev.GetPolicyId())
				}
				if ev.GetAction() != eventv1.Action_ACTION_BLOCK {
					t.Fatalf("expected ACTION_BLOCK, got %v", ev.GetAction())
				}
				if len(ev.GetMatches()) == 0 {
					t.Fatalf("expected matches, got none")
				}
				// Ensure matches were truncated to fit under 8192 bytes
				if len(ev.GetMatches()) >= 60 {
					t.Fatalf("expected matches to be truncated below 60, got %d", len(ev.GetMatches()))
				}
				if ev.GetLayerScores()["protocol"] != 50 {
					t.Fatalf("expected protocol score 50, got %d", ev.GetLayerScores()["protocol"])
				}
				if ev.GetLayerScores()["anomaly"] != 150 {
					t.Fatalf("expected anomaly score 150, got %d", ev.GetLayerScores()["anomaly"])
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := readGolden(t, tt.name)
			if len(b) > MaxDatagram {
				t.Fatalf("golden file %s is %d bytes, exceeds MaxDatagram %d", tt.name, len(b), MaxDatagram)
			}
			ev, ok := Decode(b)
			if !ok {
				t.Fatalf("Decode failed for golden file %s (%d bytes)", tt.name, len(b))
			}
			tt.validate(t, ev)
		})
	}
}
