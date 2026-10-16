package replay

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"testing"

	"github.com/strata/strata/control-plane/store"
)

type proofStore struct {
	v  store.PolicyVersion
	op store.Operation
	b  store.Bundle
}

func (p *proofStore) GetPolicyVersion(context.Context, string, int) (store.PolicyVersion, error) {
	return p.v, nil
}
func (p *proofStore) GetOperation(context.Context, string) (store.Operation, error) { return p.op, nil }
func (p *proofStore) LatestBundle(context.Context) (store.Bundle, error)            { return p.b, nil }

func TestReplayGateUsesApprovedOperation(t *testing.T) {
	good := Report{InputDigest: digest([]byte("inputs")), DraftSHA256: digest([]byte("draft")), BaselineSHA256: digest([]byte("base")), BaselineBundle: 4, Corpus: &Route{Samples: 10}}
	baseHash := sha256.Sum256([]byte("base"))
	baseSum := baseHash[:]
	for _, tc := range []struct {
		name   string
		change func(*proofStore, *Report)
		want   bool
	}{
		{"matching inputs", func(*proofStore, *Report) {}, true},
		{"rule or compiler change", func(_ *proofStore, r *Report) { r.InputDigest = digest([]byte("old inputs")) }, false},
		{"baseline changed", func(p *proofStore, _ *Report) { p.b.Version = 5 }, false},
		{"baseline artifact changed", func(p *proofStore, _ *Report) { p.b.SHA256 = make([]byte, 32) }, false},
		{"no approved proof", func(p *proofStore, _ *Report) { p.v.ApprovedReplayID = "" }, false},
		{"pending", func(p *proofStore, _ *Report) { p.op.State = store.OpPending }, false},
		{"other policy", func(p *proofStore, _ *Report) { p.op.PolicyID = "other" }, false},
		{"other version", func(p *proofStore, _ *Report) { p.op.Version = 2 }, false},
		{"empty corpus", func(_ *proofStore, r *Report) { r.Corpus = nil }, false},
		{"old unbound result", func(_ *proofStore, r *Report) { r.InputDigest = "" }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := good
			p := &proofStore{v: store.PolicyVersion{ApprovedReplayID: "approved-op"}, op: store.Operation{ID: "approved-op", Kind: store.OpReplay, PolicyID: "example-api", Version: 1, State: store.OpDone}, b: store.Bundle{Version: 4, SHA256: baseSum}}
			tc.change(p, &r)
			raw, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			p.op.Result = raw
			err = (Gate{Store: p}).Check(t.Context(), map[string]int{"example-api": 1}, good.InputDigest)
			if (err == nil) != tc.want {
				t.Fatalf("allowed=%v err=%v", err == nil, err)
			}
		})
	}
}
