package standalone

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	eventv1 "github.com/strata/strata/agent/gen/strata/event/v1"
)

func TestUnavailableBundlePrivacyMasksPayloadInEveryLiteSink(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	exporter, err := NewEventExporter(path, "", "")
	if err != nil {
		t.Fatal(err)
	}
	defer exporter.Close()
	watcher := &BundleWatcher{}
	exporter.Privacy = watcher.Privacy
	e := &eventv1.Event{BlockId: "STR-0000-0000-0000-0001", BundleVersion: 7, PolicyId: "example-api", ClientIp: "192.0.2.123", Identity: "example-user", Path: "/private/example-secret", Host: "private.example.test", Matches: []*eventv1.Match{{Field: "ARGS:customer_id", Snippet: []byte("example-customer")}}, Headers: []*eventv1.Header{{Name: "X-Secret", Value: []byte("example-token")}}}
	if err := exporter.Export(e); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"192.0.2.123", "example-user", "example-secret", "private.example.test", "example-customer", "example-token"} {
		if strings.Contains(string(data), secret) {
			t.Fatal("unresolved privacy leaked", secret)
		}
	}
	if !strings.Contains(string(data), e.BlockId) || e.ClientIp != "192.0.2.123" {
		t.Fatal("diagnostic lost or producer mutated")
	}
}
