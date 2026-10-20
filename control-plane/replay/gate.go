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
	GetBundle(context.Context, uint64) (store.Bundle, error)
}

type Gate struct{ Store ProofStore }

// Check uses the operation bound at approval, never an unapproved newer replay.
// It runs while the deployer holds the cluster-wide bundle lock.
//
// Only what changes is checked (CP-FIX-01, PO 20/10/2026): a policy at the
// version the bundle in force already carries, under the same compiler and
// rules (rulesDigest), is skipped. Every other policy needs its approved
// replay: made with these rules, against a bundle in force where the policy
// was at the version in force now. When the rules changed, or the bundle in
// force predates rules digests, every policy needs one.
func (g Gate) Check(ctx context.Context, contents map[string]int, inputDigest, rulesDigest string) error {
	baseline, err := g.Store.LatestBundle(ctx)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("replay gate baseline: %w", err)
	}
	validDigest := func(s string) bool { v, err := hex.DecodeString(s); return err == nil && len(v) == 32 }
	if !validDigest(inputDigest) || !validDigest(rulesDigest) {
		return replayMismatch("replay gate: invalid input digests")
	}
	rulesChanged := baseline.Version == 0 || baseline.RulesDigest != rulesDigest
	for id, version := range contents {
		if !rulesChanged && baseline.Contents[id] == version {
			continue // in force already, under the same rules
		}
		v, err := g.Store.GetPolicyVersion(ctx, id, version)
		if err != nil {
			return err
		}
		if v.ApprovedReplayID == "" {
			if rulesChanged && baseline.Contents[id] == version {
				return replayMismatch("replay gate: the compiler or rules changed since policy %s v%d was approved; save it again as a new version, replay and approve it", id, version)
			}
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
		if !validDigest(proof.DraftSHA256) || !validDigest(proof.BaselineSHA256) || proof.Samples() == 0 {
			return replayMismatch("replay gate: incomplete replay result for %s v%d", id, version)
		}
		if err := g.sameGround(ctx, id, proof, baseline, inputDigest, rulesDigest); err != nil {
			return err
		}
	}
	return nil
}

// sameGround checks that a replay compared the policy against what is in
// force now: the same rules, and the policy at the same version.
func (g Gate) sameGround(ctx context.Context, id string, proof Report, baseline store.Bundle, inputDigest, rulesDigest string) error {
	stale := func() error {
		return replayMismatch("replay gate: inputs or baseline changed for %s since its replay; replay and approve a new version", id)
	}
	if proof.RulesDigest == "" {
		// a replay from before rules digests: only the exact old match holds
		if proof.InputDigest != inputDigest || proof.BaselineBundle != baseline.Version {
			return stale()
		}
	} else {
		if proof.RulesDigest != rulesDigest {
			return stale()
		}
		if proof.BaselineBundle != baseline.Version {
			if proof.BaselineBundle == 0 || baseline.Version == 0 {
				return stale()
			}
			then, err := g.Store.GetBundle(ctx, proof.BaselineBundle)
			if err != nil {
				return replayMismatch("replay gate: baseline bundle %d of %s: %v", proof.BaselineBundle, id, err)
			}
			if then.RulesDigest != baseline.RulesDigest || then.Contents[id] != baseline.Contents[id] {
				return stale()
			}
			return nil
		}
	}
	if baseline.Version != 0 && proof.BaselineSHA256 != hex.EncodeToString(baseline.SHA256) {
		return replayMismatch("replay gate: baseline artifact changed for %s", id)
	}
	return nil
}

func replayMismatch(format string, args ...any) error {
	return &policy.ReplayError{Msg: fmt.Sprintf(format, args...)}
}
