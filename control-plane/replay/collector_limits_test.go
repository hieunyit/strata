package replay

import (
	"context"
	"fmt"
	"testing"

	eventv1 "github.com/strata/strata/agent/gen/strata/event/v1"
)

func TestCollectorLimitsAndAuthorization(t *testing.T) {
	c := NewCollector(&Store{Objects: &memObjects{m: map[string][]byte{}}})
	sample := func(p, key string) *eventv1.ReplaySample {
		return &eventv1.ReplaySample{Policy: []byte(p), AnonKeyId: key, Body: make([]byte, 1000)}
	}
	c.Add(t.Context(), "node-a", []*eventv1.ReplaySample{sample("example-api", "k1")})
	if len(c.files) != 0 {
		t.Fatal("accepted samples without authorization")
	}
	c.Authorize = func(context.Context, string) (string, map[string]bool, error) {
		return "k1", map[string]bool{"example-api": true}, nil
	}
	c.MaxBytes, c.MaxNodeBytes, c.MaxFiles = 10000, 7000, 2
	c.Add(t.Context(), "node-a", []*eventv1.ReplaySample{nil, sample("unknown", "k1"), sample("example-api", "old"),
		{Policy: []byte("example-api"), AnonKeyId: "k1", Body: make([]byte, 8193)}})
	if len(c.files) != 0 {
		t.Fatal("invalid samples retained")
	}
	for i := 0; i < 100; i++ {
		c.Add(t.Context(), fmt.Sprintf("node-%d", i), []*eventv1.ReplaySample{sample("example-api", "k1")})
	}
	if len(c.files) > 2 || c.bytes > c.MaxBytes {
		t.Fatalf("unbounded files/bytes: %d/%d", len(c.files), c.bytes)
	}
	for i := 0; i < 100; i++ {
		c.Add(t.Context(), "node-0", []*eventv1.ReplaySample{sample("example-api", "k1")})
	}
	if c.nodeBytes["node-0"] > c.MaxNodeBytes {
		t.Fatal("per-node budget exceeded")
	}
	c.FlushAll(t.Context())
	if c.bytes != 0 || len(c.nodeBytes) != 0 || len(c.files) != 0 {
		t.Fatal("flush did not release budgets")
	}
	if c.Dropped.Load() == 0 || c.Written.Load() == 0 {
		t.Fatal("missing drop/write accounting")
	}
}
