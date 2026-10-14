package corpus

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/strata/strata/tools/strata-rules/internal/runner"
)

func TestPilotIsDeterministicAndShaped(t *testing.T) {
	var a, b bytes.Buffer
	if err := Pilot(1, 50, &a); err != nil {
		t.Fatal(err)
	}
	if err := Pilot(1, 50, &b); err != nil {
		t.Fatal(err)
	}
	if a.String() != b.String() {
		t.Fatal("same seed, different corpus")
	}
	routes := map[string]int{}
	for _, line := range strings.Split(strings.TrimSpace(a.String()), "\n") {
		var r runner.Request
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatal(err)
		}
		routes[r.URI]++
		ct, _ := r.Headers["Content-Type"].(string)
		switch r.URI {
		case "/v1/verify":
			var body map[string]any
			if ct != "application/json" || json.Unmarshal([]byte(r.Body), &body) != nil || body["document_id"] == nil {
				t.Fatalf("verify request %s: %q %q", r.ID, ct, r.Body)
			}
		case "/v1/upload":
			i := strings.Index(ct, "boundary=")
			if i < 0 || !strings.HasSuffix(r.Body, "--"+ct[i+len("boundary="):]+"--\r\n") || !strings.Contains(r.Body, `filename="`) {
				t.Fatalf("upload request %s is not a closed multipart body", r.ID)
			}
		default:
			t.Fatalf("unexpected route %q", r.URI)
		}
	}
	if routes["/v1/verify"] == 0 || routes["/v1/upload"] == 0 {
		t.Fatalf("both routes expected: %v", routes)
	}
}
