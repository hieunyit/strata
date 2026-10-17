package fleet

import (
	"context"
	"errors"
	"time"

	"github.com/strata/strata/control-plane/store"
)

type stagingRolloutStore interface {
	StartStagingRollout(context.Context, string, []string, []float64, time.Duration, store.Audit) (store.Rollout, []string, error)
	LatestBundle(context.Context) (store.Bundle, error)
}

// StartStaging recovers a durable intent without going through Start, whose
// ordinary deploy semantics deliberately create/supersede rollouts. A repeated
// call resends only currently unacknowledged notices from the linked rollout.
func (r *Rollouts) StartStaging(ctx context.Context, a store.StagingAction) (store.Rollout, error) {
	st, ok := r.Store.(stagingRolloutStore)
	if !ok {
		return store.Rollout{}, errors.New("fleet: staging rollout store unavailable")
	}
	nodes, err := r.Store.EnrolledNodes(ctx)
	if err != nil {
		return store.Rollout{}, err
	}
	ro, first, err := st.StartStagingRollout(ctx, a.ID, nodes, r.Waves, r.Soak, store.Audit{Actor: "rule-health", Channel: "system"})
	if err != nil {
		return store.Rollout{}, err
	}
	b, err := st.LatestBundle(ctx)
	if err != nil {
		return ro, err
	}
	if b.Version != a.BundleVersion || ro.BundleVersion != a.BundleVersion {
		return ro, store.ErrStagingConflict
	}
	r.notify(first, b)
	return ro, nil
}
