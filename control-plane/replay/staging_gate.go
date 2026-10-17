package replay

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"

	"github.com/strata/strata/control-plane/store"
)

type stagingProofStore interface {
	ProofStore
	StagingRoot(context.Context, uint64) (store.Bundle, error)
	GetBundle(context.Context, uint64) (store.Bundle, error)
}

// CheckStaging validates the original approved replay at a deployed ordinary
// root, followed only by durable additive derivations. It grants no ordinary
// redeploy: Check keeps its existing current-baseline requirement unchanged.
// The writer separately requires ACTIVE source ACKs, immutable opt-in, fresh
// threshold evidence and a capture matching source.InputDigest.
func (g Gate) CheckStaging(ctx context.Context, source store.Bundle) error {
	st, ok := g.Store.(stagingProofStore)
	if !ok {
		return errors.New("staging gate: proof store unavailable")
	}
	current, err := st.LatestBundle(ctx)
	if err != nil {
		return err
	}
	if source.Version == 0 || source.Version != current.Version || source.InputDigest != current.InputDigest || !bytes.Equal(source.SHA256, current.SHA256) || !maps.Equal(source.Contents, current.Contents) {
		return replayMismatch("staging gate: stale source")
	}
	root, err := st.StagingRoot(ctx, source.Version)
	if err != nil {
		return err
	}
	if root.Version == 0 || root.Version > source.Version || len(root.Contents) < 1 || len(root.Contents) > 4096 || !maps.Equal(root.Contents, source.Contents) {
		return replayMismatch("staging gate: invalid source ancestry")
	}
	validDigest := func(s string) bool { v, err := hex.DecodeString(s); return err == nil && len(v) == 32 }
	if !validDigest(root.InputDigest) {
		return replayMismatch("staging gate: root has no captured replay inputs")
	}
	for id, version := range root.Contents {
		v, err := st.GetPolicyVersion(ctx, id, version)
		if err != nil {
			return err
		}
		if v.ApprovedReplayID == "" || (v.State != store.VersionApproved && v.State != store.VersionDeployed) {
			return replayMismatch("staging gate: missing approved replay for %s v%d", id, version)
		}
		op, err := st.GetOperation(ctx, v.ApprovedReplayID)
		if err != nil {
			return err
		}
		if op.ID != v.ApprovedReplayID || op.Kind != store.OpReplay || op.PolicyID != id || op.Version != version || op.State != store.OpDone {
			return replayMismatch("staging gate: invalid approved operation")
		}
		var proof Report
		if err = json.Unmarshal(op.Result, &proof); err != nil {
			return replayMismatch("staging gate: invalid approved replay result")
		}
		if proof.InputDigest != root.InputDigest || proof.BaselineBundle != root.Version-1 || !validDigest(proof.DraftSHA256) || !validDigest(proof.BaselineSHA256) || proof.Samples() == 0 {
			return replayMismatch("staging gate: root replay inputs or baseline differ")
		}
		if proof.BaselineBundle != 0 {
			baseline, err := st.GetBundle(ctx, proof.BaselineBundle)
			if err != nil {
				return err
			}
			if proof.BaselineSHA256 != hex.EncodeToString(baseline.SHA256) {
				return replayMismatch("staging gate: original baseline artifact differs")
			}
		}
	}
	return nil
}
