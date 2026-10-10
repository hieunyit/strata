package fleet

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/strata/strata/control-plane/store"
)

// RolloutStore is the part of store.Store rollouts use.
type RolloutStore interface {
	EnrolledNodes(ctx context.Context) ([]string, error)
	CreateRollout(ctx context.Context, version uint64, nodes []string, plan []float64, soak time.Duration, a store.Audit) (store.Rollout, []string, error)
	ActiveRollouts(ctx context.Context) ([]store.Rollout, error)
	AdvanceRollout(ctx context.Context, id int64) ([]string, error)
	MarkWaveDone(ctx context.Context, id int64, at time.Time) error
	SetRolloutState(ctx context.Context, id int64, to, reason string, from []string, a store.Audit) (store.Rollout, error)
	DesiredBundle(ctx context.Context, node string) (store.Bundle, error)
}

// DefaultWaves: one node, then 10% of the nodes, then all
// (nginx-module.md › Phân phối bundle).
var DefaultWaves = []float64{0, 0.10, 1}

// Rollouts moves bundle rollouts through their waves: a wave starts by
// telling its nodes (BundleAvailable); when every node of it reports
// ACTIVE and the soak time has passed, the next wave starts; a FAILED node
// stops the rollout.
type Rollouts struct {
	Store    RolloutStore
	Presence *Presence
	Waves    []float64
	Soak     time.Duration
	Now      func() time.Time
	kick     chan struct{}
}

// NewRollouts returns a controller; call Run.
func NewRollouts(st RolloutStore, p *Presence, waves []float64, soak time.Duration) *Rollouts {
	if len(waves) == 0 {
		waves = DefaultWaves
	}
	return &Rollouts{Store: st, Presence: p, Waves: waves, Soak: soak, Now: time.Now, kick: make(chan struct{}, 1)}
}

// Kick asks for a check now (a node reported a status).
func (r *Rollouts) Kick() {
	select {
	case r.kick <- struct{}{}:
	default:
	}
}

// Start rolls bundle b out to every enrolled node.
func (r *Rollouts) Start(ctx context.Context, b store.Bundle, a store.Audit) (store.Rollout, error) {
	nodes, err := r.Store.EnrolledNodes(ctx)
	if err != nil {
		return store.Rollout{}, err
	}
	a.Action = "/strata.admin.v1.RolloutService/StartRollout"
	ro, first, err := r.Store.CreateRollout(ctx, b.Version, nodes, r.Waves, r.Soak, a)
	if err != nil {
		return store.Rollout{}, err
	}
	log.Printf("[INFO] fleet: rollout %d of bundle %d: waves %v over %d nodes", ro.ID, b.Version, ro.Waves, len(nodes))
	r.notify(first, b)
	return ro, nil
}

func (r *Rollouts) notify(nodes []string, b store.Bundle) {
	for _, n := range nodes {
		// An agent that is not connected now gets it in reply to Hello.
		r.Presence.Notify(n, BundleAvailable(b, false))
	}
}

// Run checks the rollouts every second and when kicked, until ctx ends.
func (r *Rollouts) Run(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-r.kick:
		}
		if err := r.Tick(ctx); err != nil && ctx.Err() == nil {
			log.Printf("[WARN] fleet: rollouts: %v", err)
		}
	}
}

// Tick advances what can advance.
func (r *Rollouts) Tick(ctx context.Context) error {
	ros, err := r.Store.ActiveRollouts(ctx)
	if err != nil {
		return err
	}
	for _, ro := range ros {
		if err := r.step(ctx, ro); err != nil {
			return fmt.Errorf("rollout %d: %w", ro.ID, err)
		}
	}
	return nil
}

func (r *Rollouts) step(ctx context.Context, ro store.Rollout) error {
	all := true
	for _, n := range ro.Nodes {
		if n.Wave != ro.CurrentWave {
			continue
		}
		if n.State == "FAILED" {
			reason := fmt.Sprintf("node %s failed bundle %d: %s", n.NodeID, ro.BundleVersion, n.Error)
			_, err := r.Store.SetRolloutState(ctx, ro.ID, store.RolloutFailed, reason, []string{store.RolloutRunning}, store.Audit{})
			if err == nil {
				log.Printf("[WARN] fleet: rollout %d stopped: %s", ro.ID, reason)
			}
			if errors.Is(err, store.ErrRolloutState) {
				return nil
			}
			return err
		}
		all = all && n.State == "ACTIVE"
	}
	if !all {
		return nil
	}
	now := r.Now()
	if ro.WaveDoneAt == nil {
		if err := r.Store.MarkWaveDone(ctx, ro.ID, now); err != nil {
			return err
		}
		if ro.SoakSeconds > 0 {
			return nil
		}
	} else if now.Before(ro.WaveDoneAt.Add(time.Duration(ro.SoakSeconds) * time.Second)) {
		return nil
	}
	next, err := r.Store.AdvanceRollout(ctx, ro.ID)
	if errors.Is(err, store.ErrRolloutState) {
		return nil
	}
	if err != nil {
		return err
	}
	if len(next) == 0 {
		log.Printf("[INFO] fleet: rollout %d of bundle %d done", ro.ID, ro.BundleVersion)
		return nil
	}
	log.Printf("[INFO] fleet: rollout %d wave %d: %v", ro.ID, ro.CurrentWave+1, next)
	b, err := r.Store.DesiredBundle(ctx, next[0])
	if err != nil {
		return err
	}
	r.notify(next, b)
	return nil
}
