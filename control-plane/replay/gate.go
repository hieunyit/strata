package replay

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/strata/strata/control-plane/policy"
	"github.com/strata/strata/control-plane/store"
)

type ProofStore interface {
	GetPolicyVersion(context.Context, string, int) (store.PolicyVersion, error)
	GetOperation(context.Context, string) (store.Operation, error)
	LatestBundle(context.Context) (store.Bundle, error)
}

type Gate struct{ Store ProofStore }

// Check uses the operation bound at approval, never an unapproved newer replay.
// It runs while the deployer holds the cluster-wide bundle lock.
func (g Gate) Check(ctx context.Context, contents map[string]int, inputDigest string) error {
	baseline, err := g.Store.LatestBundle(ctx)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("replay gate baseline: %w", err)
	}
	for id, version := range contents {
		v, err := g.Store.GetPolicyVersion(ctx, id, version)
		if err != nil {
			return err
		}
		if v.ApprovedReplayID == "" {
			return replayMismatch("replay gate: policy %s v%d has no replay bound to approval; submit and approve a new version", id, version)
		}
		op, err := g.Store.GetOperation(ctx, v.ApprovedReplayID)
		if err != nil {
			return err
		}
		if op.ID != v.ApprovedReplayID || op.Kind != store.OpReplay || op.PolicyID != id || op.Version != version || op.State != store.OpDone {
			return replayMismatch("replay gate: invalid approved operation for %s v%d", id, version)
		}
		var proof Report
		if err := json.Unmarshal(op.Result, &proof); err != nil {
			return replayMismatch("replay gate: invalid result: %v", err)
		}
		if len(inputDigest) != 64 || proof.InputDigest != inputDigest || proof.BaselineBundle != baseline.Version || len(proof.DraftSHA256) != 64 || len(proof.BaselineSHA256) != 64 || proof.Samples() == 0 {
			return replayMismatch("replay gate: inputs or baseline changed for %s v%d; replay and approve a new version", id, version)
		}
		if baseline.Version != 0 && proof.BaselineSHA256 != hex.EncodeToString(baseline.SHA256) {
			return replayMismatch("replay gate: baseline artifact changed for %s", id)
		}
	}
	return nil
}

func replayMismatch(format string, args ...any) error {
	return &policy.ReplayError{Msg: fmt.Sprintf(format, args...)}
}
