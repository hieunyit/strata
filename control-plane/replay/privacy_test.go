package replay

import (
	"context"
	"encoding/json"
	eventv1 "github.com/strata/strata/agent/gen/strata/event/v1"
	"google.golang.org/protobuf/proto"
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

func TestCollectorAccountsForRetainedRedactionOutput(t *testing.T) {
	sample := &eventv1.ReplaySample{Policy: []byte("example-api"), AnonKeyId: "example-key", Headers: []byte(`[]`), Body: []byte(`{` + strings.TrimSuffix(strings.Repeat(`"pin":0,`, 200), ",") + `}`)}
	before := int64(2*proto.Size(sample) + 1024)
	after := retainedRecordBytes(privateRecord(RecordOf("example-node", sample), nil))
	if after <= before {
		t.Fatalf("fixture must expand to exceed the wire estimate: %d <= %d", after, before)
	}
	c := NewCollector(nil)
	c.Authorize = func(context.Context, string) (string, map[string]bool, error) {
		return "example-key", map[string]bool{"example-api": true}, nil
	}
	c.Privacy = func(context.Context, string, uint64) (*privacy.Filter, error) { return nil, nil }
	c.MaxBytes = before
	c.Add(context.Background(), "example-node", []*eventv1.ReplaySample{sample})
	if c.Dropped.Load() != 1 || c.bytes != 0 {
		t.Fatal("post-redaction size bypassed buffer cap")
	}
}

func TestReplayInvalidHeadersFailClosedAndRawClientsAreNotRetained(t *testing.T) {
	r := privateRecord(Record{Headers: "invalid", Body: []byte(`{"customer_id":"example-secret"}`), Client: "192.0.2.1"}, nil)
	if string(r.Body) != privacy.Mask || r.Client != privacy.Mask {
		t.Fatal("unknown replay structure retained sensitive input")
	}
	token := "~h:123456abcdef1234:a12"
	r = privateRecord(Record{Headers: `[]`, Client: token, Body: []byte("1=1 AND 2=2")}, nil)
	if r.Client != token || string(r.Body) != "1=1 AND 2=2" {
		t.Fatal("ordinary replay semantics changed")
	}
}
