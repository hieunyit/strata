package replay

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"

	"github.com/strata/strata/control-plane/store"
)

type proofStore struct {
	v       store.PolicyVersion
	op      store.Operation
	b       store.Bundle
	bundles map[uint64]store.Bundle
}

func (p *proofStore) GetPolicyVersion(context.Context, string, int) (store.PolicyVersion, error) {
	return p.v, nil
}
func (p *proofStore) GetOperation(context.Context, string) (store.Operation, error) { return p.op, nil }
func (p *proofStore) LatestBundle(context.Context) (store.Bundle, error) {
	if p.b.Version == 0 {
		return store.Bundle{}, store.ErrNotFound
	}
	return p.b, nil
}
func (p *proofStore) GetBundle(_ context.Context, v uint64) (store.Bundle, error) {
	if b, ok := p.bundles[v]; ok {
		return b, nil
	}
	return store.Bundle{}, store.ErrNotFound
}

// Deploying example-api v2 while bundle 4 (rules R, example-api v1) is in
// force: the approved replay of v2 decides.
func TestReplayGateUsesApprovedOperation(t *testing.T) {
	rules := digest([]byte("rules"))
	good := Report{InputDigest: digest([]byte("inputs")), RulesDigest: rules, DraftSHA256: digest([]byte("draft")),
		BaselineSHA256: digest([]byte("base")), BaselineBundle: 4, Corpus: &Route{Samples: 10}}
	baseHash := sha256.Sum256([]byte("base"))
	baseSum := baseHash[:]
	for _, tc := range []struct {
		name   string
		change func(*proofStore, *Report)
		want   bool
	}{
		{"matching inputs", func(*proofStore, *Report) {}, true},
		{"other policies changed since: input digest differs, rules the same", func(_ *proofStore, r *Report) { r.InputDigest = digest([]byte("old inputs")) }, true},
		{"rule or compiler change", func(_ *proofStore, r *Report) { r.RulesDigest = digest([]byte("old rules")) }, false},
		{"baseline artifact changed", func(p *proofStore, _ *Report) { p.b.SHA256 = make([]byte, 32) }, false},
		{"no approved proof", func(p *proofStore, _ *Report) { p.v.ApprovedReplayID = "" }, false},
		{"pending", func(p *proofStore, _ *Report) { p.op.State = store.OpPending }, false},
		{"other policy", func(p *proofStore, _ *Report) { p.op.PolicyID = "other" }, false},
		{"other version", func(p *proofStore, _ *Report) { p.op.Version = 1 }, false},
		{"empty corpus", func(_ *proofStore, r *Report) { r.Corpus = nil }, false},
		{"unbound result", func(_ *proofStore, r *Report) { r.InputDigest, r.RulesDigest = "", "" }, false},
		// another policy deployed after the replay: bundle 5 carries the
		// same example-api v1 and the same rules, so the comparison holds
		{"newer bundle, same ground", func(p *proofStore, _ *Report) {
			p.bundles[4] = p.b
			p.b = store.Bundle{Version: 5, RulesDigest: rules, SHA256: make([]byte, 32), Contents: map[string]int{"example-api": 1, "example-web": 3}}
		}, true},
		{"newer bundle, policy deployed at another version since", func(p *proofStore, _ *Report) {
			p.bundles[4] = p.b
			p.b = store.Bundle{Version: 5, RulesDigest: rules, SHA256: make([]byte, 32), Contents: map[string]int{"example-api": 3}}
		}, false},
		{"newer bundle, rules in force changed", func(p *proofStore, _ *Report) {
			p.bundles[4] = p.b
			p.b = store.Bundle{Version: 5, RulesDigest: digest([]byte("other rules in force")), SHA256: make([]byte, 32), Contents: map[string]int{"example-api": 1}}
		}, false},
		{"replay before rules digests, exact old match", func(_ *proofStore, r *Report) { r.RulesDigest = "" }, true},
		{"replay before rules digests, inputs changed", func(_ *proofStore, r *Report) { r.RulesDigest, r.InputDigest = "", digest([]byte("old")) }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := good
			p := &proofStore{v: store.PolicyVersion{ApprovedReplayID: "approved-op"},
				op:      store.Operation{ID: "approved-op", Kind: store.OpReplay, PolicyID: "example-api", Version: 2, State: store.OpDone},
				b:       store.Bundle{Version: 4, RulesDigest: rules, SHA256: baseSum, Contents: map[string]int{"example-api": 1}},
				bundles: map[uint64]store.Bundle{}}
			tc.change(p, &r)
			raw, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			p.op.Result = raw
			err = (Gate{Store: p}).Check(t.Context(), map[string]int{"example-api": 2}, good.InputDigest, rules)
			if (err == nil) != tc.want {
				t.Fatalf("allowed=%v err=%v", err == nil, err)
			}
		})
	}
}

// CP-FIX-01: a policy the bundle in force already carries, under the same
// rules, needs nothing, even a version approved before replay pins existed;
// when the rules changed (or the bundle in force predates rules digests),
// it needs a new approved version.
func TestReplayGateChecksOnlyWhatChanged(t *testing.T) {
	rules := digest([]byte("rules"))
	inputs := digest([]byte("inputs"))
	p := &proofStore{b: store.Bundle{Version: 7, RulesDigest: rules, SHA256: make([]byte, 32), Contents: map[string]int{"legacy-api": 3}},
		bundles: map[uint64]store.Bundle{}}
	if err := (Gate{Store: p}).Check(t.Context(), map[string]int{"legacy-api": 3}, inputs, rules); err != nil {
		t.Fatalf("unchanged policy refused: %v", err)
	}
	err := (Gate{Store: p}).Check(t.Context(), map[string]int{"legacy-api": 3}, inputs, digest([]byte("new rules")))
	if err == nil || !strings.Contains(err.Error(), "compiler or rules changed") {
		t.Fatalf("rule change: %v", err)
	}
	p.b.RulesDigest = "" // recorded before rules digests
	if err := (Gate{Store: p}).Check(t.Context(), map[string]int{"legacy-api": 3}, inputs, rules); err == nil {
		t.Fatal("unknown rules in force treated as unchanged")
	}
	p.b = store.Bundle{}
	if err := (Gate{Store: p}).Check(t.Context(), map[string]int{"legacy-api": 3}, inputs, rules); err == nil {
		t.Fatal("first bundle without a replay")
	}
	p.b = store.Bundle{Version: 7, RulesDigest: rules, SHA256: make([]byte, 32), Contents: map[string]int{"legacy-api": 3}}
	if err := (Gate{Store: p}).Check(t.Context(), map[string]int{"legacy-api": 3}, "short", rules); err == nil {
		t.Fatal("invalid digest accepted")
	}
}
