package replay

import (
	"context"
	"testing"

	eventv1 "github.com/strata/strata/agent/gen/strata/event/v1"
)

// W12-N-01: samples from the nodes become sample files, one per policy,
// node and key, with the enrolled node id and the canary column.
func TestCollectorWritesSampleFiles(t *testing.T) {
	objs := &memObjects{m: map[string][]byte{}}
	c := NewCollector(&Store{Objects: objs})
	c.MaxRows = 3
	c.Authorize = func(context.Context, string) (string, map[string]bool, error) {
		return "k1", map[string]bool{"example-api": true, "example-web": true}, nil
	}
	s := func(policy string, canary eventv1.CanaryGroup) *eventv1.ReplaySample {
		return &eventv1.ReplaySample{AnonKeyId: "k1", TsMs: 1791939600000, Policy: []byte(policy), Method: []byte("POST"),
			RawUri: []byte("/v1/x?q=1"), Client: []byte("~h:0011223344556677:s12"), Headers: []byte(`[["Host","api.example.test"]]`),
			Body: []byte("a=1"), BodyLen: 3, Action: []byte("log"), Rules: []byte("941100"), Canary: canary}
	}
	ctx := context.Background()
	c.Add(ctx, "node-1", []*eventv1.ReplaySample{s("example-api", eventv1.CanaryGroup_CANARY_GROUP_ENFORCE), s("example-api", 0), s("example-web", 0)})
	if len(objs.m) != 0 {
		t.Fatalf("written before MaxRows: %v", objs.m)
	}
	c.Add(ctx, "node-1", []*eventv1.ReplaySample{s("example-api", eventv1.CanaryGroup_CANARY_GROUP_SHADOW)})
	if len(objs.m) != 1 {
		t.Fatalf("%d files after 3 samples of example-api", len(objs.m))
	}
	c.FlushAll(ctx)
	if len(objs.m) != 2 || c.Received.Load() != 4 || c.Written.Load() != 4 {
		t.Fatalf("%d files, %d/%d", len(objs.m), c.Received.Load(), c.Written.Load())
	}
	for k, b := range objs.m {
		keyID, recs, err := ReadParquet(b)
		if err != nil || keyID != "k1" {
			t.Fatalf("%s: %v %v", k, keyID, err)
		}
		if recs[0].Policy == "example-api" {
			if len(recs) != 3 || recs[0].NodeID != "node-1" || recs[0].Canary != "enforce" || recs[1].Canary != "" || recs[2].Canary != "shadow" ||
				recs[0].RawURI != "/v1/x?q=1" || string(recs[0].Body) != "a=1" || recs[0].Rules != "941100" {
				t.Fatalf("%s: %+v", k, recs)
			}
		}
	}
}
