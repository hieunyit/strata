package replay

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/strata/strata/control-plane/store"
)

type stagingProofFixture struct {
	proofStore
	root, baseline store.Bundle
}

func (s *stagingProofFixture) StagingRoot(context.Context, uint64) (store.Bundle, error) {
	return s.root, nil
}
func (s *stagingProofFixture) GetBundle(context.Context, uint64) (store.Bundle, error) {
	return s.baseline, nil
}

func TestStagingGateUsesApprovedRootWithoutWeakeningDeploy(t *testing.T) {
	for _, tc := range []struct {
		name  string
		alter func(*stagingProofFixture, *Report, *store.Bundle)
		want  bool
	}{
		{"valid additive descendant", func(*stagingProofFixture, *Report, *store.Bundle) {}, true},
		{"missing original proof", func(s *stagingProofFixture, _ *Report, _ *store.Bundle) { s.v.ApprovedReplayID = "" }, false},
		{"unapproved version", func(s *stagingProofFixture, _ *Report, _ *store.Bundle) { s.v.State = store.VersionDraft }, false},
		{"newer unapproved operation", func(s *stagingProofFixture, _ *Report, _ *store.Bundle) { s.op.ID = "new-op" }, false},
		{"pending replay", func(s *stagingProofFixture, _ *Report, _ *store.Bundle) { s.op.State = store.OpPending }, false},
		{"other version", func(s *stagingProofFixture, _ *Report, _ *store.Bundle) { s.op.Version = 2 }, false},
		{"different root inputs", func(_ *stagingProofFixture, r *Report, _ *store.Bundle) { r.InputDigest = digest([]byte("changed")) }, false},
		{"different original baseline", func(_ *stagingProofFixture, r *Report, _ *store.Bundle) { r.BaselineBundle = 3 }, false},
		{"original artifact changed", func(s *stagingProofFixture, _ *Report, _ *store.Bundle) { s.baseline.SHA256 = make([]byte, 32) }, false},
		{"empty sample proof", func(_ *stagingProofFixture, r *Report, _ *store.Bundle) { r.Corpus = nil }, false},
		{"stale current source", func(_ *stagingProofFixture, _ *Report, b *store.Bundle) { b.Version-- }, false},
		{"forged source bytes", func(_ *stagingProofFixture, _ *Report, b *store.Bundle) { b.SHA256 = make([]byte, 32) }, false},
		{"changed policy set in ancestry", func(s *stagingProofFixture, _ *Report, _ *store.Bundle) {
			s.root.Contents = map[string]int{"example-api": 2}
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sum := func(s string) []byte {
				h := digest([]byte(s))
				b := make([]byte, 32)
				for i := range b {
					b[i] = h[i]
				}
				return b
			}
			rootDigest := digest([]byte("root inputs"))
			baseline := sum("baseline")
			report := Report{InputDigest: rootDigest, DraftSHA256: digest([]byte("draft")), BaselineSHA256: "", BaselineBundle: 4, Corpus: &Route{Samples: 100}}
			// Metadata SHA is bytes, whereas report SHA is hex.
			report.BaselineSHA256 = hex.EncodeToString(baseline)
			source := store.Bundle{Version: 6, InputDigest: digest([]byte("derived inputs")), SHA256: sum("derived"), Contents: map[string]int{"example-api": 1}}
			s := &stagingProofFixture{proofStore: proofStore{v: store.PolicyVersion{State: store.VersionDeployed, ApprovedReplayID: "approved-op"}, op: store.Operation{ID: "approved-op", Kind: store.OpReplay, PolicyID: "example-api", Version: 1, State: store.OpDone}, b: source}, root: store.Bundle{Version: 5, InputDigest: rootDigest, Contents: map[string]int{"example-api": 1}}, baseline: store.Bundle{Version: 4, SHA256: baseline}}
			tc.alter(s, &report, &source)
			raw, err := json.Marshal(report)
			if err != nil {
				t.Fatal(err)
			}
			s.op.Result = raw
			gate := Gate{Store: s}
			if err = gate.CheckStaging(t.Context(), source); (err == nil) != tc.want {
				t.Fatalf("allowed=%v err=%v", err == nil, err)
			}
			if tc.want {
				if err = gate.Check(t.Context(), source.Contents, source.InputDigest); err == nil {
					t.Fatal("ordinary gate accepted old baseline/proof")
				}
			}
		})
	}
}
