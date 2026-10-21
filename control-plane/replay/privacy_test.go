package replay

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/strata/strata/agent/pkg/privacy"
)

func TestReplaySinkUsesPolicyPrivacyWithoutDiscardingOrdinaryStructure(t *testing.T) {
	f, err := privacy.New([]string{"customer_id"}, []string{`PRIVATE-[0-9]+`})
	if err != nil {
		t.Fatal(err)
	}
	r := Record{RawURI: "/api?customer_id=example-customer&limit=10", URI: "/api", Args: "password=example-password&limit=10", Headers: `[["Authorization","example-token"],["Content-Type","application/json"]]`, Body: []byte(`{"customer_id":"example-customer","q":"PRIVATE-123","limit":10}`)}
	r = privateRecord(r, f)
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"example-customer", "example-password", "example-token", "PRIVATE-123"} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("replay sink leaked secret", secret)
		}
	}
	if !strings.Contains(r.RawURI, "limit=10") || !strings.Contains(r.Headers, "Content-Type") || r.URI != "/api" {
		t.Fatal("ordinary replay structure lost")
	}
}
