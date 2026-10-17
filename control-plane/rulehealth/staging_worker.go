package rulehealth

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/strata/strata/control-plane/policy"
	"github.com/strata/strata/control-plane/store"
)

type StagingWorkerStore interface {
	LatestBundle(context.Context) (store.Bundle, error)
	LatestStagingAction(context.Context) (store.StagingAction, error)
	StagingSourceReady(context.Context, uint64) (bool, error)
	BundlePolicies(context.Context, uint64) ([]store.Policy, error)
	StagedRules(context.Context, map[string]int) (map[string][]uint32, error)
	StagingCandidates(context.Context, uint64, []store.StagingScope, string, uint32, int) ([]store.StagingCandidate, error)
}

// StagingWorker reads only approved active source versions, pages durable FP
// candidates, and asks the separately guarded writer to record one additive
// action per tick. Cursor state is just scheduling; authority/jobs are durable.
// A fresh replica recovers publication first and cannot restore enforcement.
type StagingWorker struct {
	Store       StagingWorkerStore
	Writer      *policy.StagingDeployer
	Evaluate    func(context.Context, policy.Spec, uint32, string, uint64, time.Time) (Evaluation, error)
	Publish     func(context.Context, store.StagingAction) (store.Rollout, error)
	Now         func() time.Time
	mu          sync.Mutex
	source      uint64
	afterPolicy string
	afterRule   uint32
}

func (w *StagingWorker) Tick(ctx context.Context) error {
	if !w.mu.TryLock() {
		return ErrBusy
	}
	defer w.mu.Unlock()
	if w.Store == nil || w.Writer == nil || w.Evaluate == nil || w.Publish == nil {
		return ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	source, err := w.Store.LatestBundle(ctx)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	intent, err := w.Store.LatestStagingAction(ctx)
	if err == nil {
		rollout, err := w.Publish(ctx, intent)
		if err != nil {
			return err
		}
		if rollout.State != store.RolloutDone {
			return nil
		}
	} else if !errors.Is(err, store.ErrNotFound) {
		return err
	}
	ready, err := w.Store.StagingSourceReady(ctx, source.Version)
	if err != nil || !ready {
		return err
	}
	ps, err := w.Store.BundlePolicies(ctx, source.Version)
	if err != nil {
		return err
	}
	staged, err := w.Store.StagedRules(ctx, source.Contents)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	if w.Now != nil {
		now = w.Now().UTC().Truncate(time.Microsecond)
	}
	scopes := make([]store.StagingScope, 0)
	type target struct {
		id      string
		version int
		spec    policy.Spec
	}
	targets := make(map[string]target, len(ps))
	for _, p := range ps {
		if !policy.NamePattern.MatchString(p.Name) {
			return fmt.Errorf("staging worker: invalid source policy name")
		}
		spec, err := policy.Parse(p.Spec)
		if err != nil {
			return err
		}
		a := spec.AutoStaging
		if spec.Mode != "enforce" || a == nil || !a.Enabled {
			continue
		}
		targets[p.Name] = target{p.ID, p.CurrentVersion, spec}
		for _, rule := range a.RuleIDs {
			found := false
			for _, id := range staged[p.ID] {
				if id == rule {
					found = true
					break
				}
			}
			if found {
				continue
			}
			scopes = append(scopes, store.StagingScope{PolicyName: p.Name, RuleID: rule, From: now.Add(-time.Duration(a.WindowSeconds) * time.Second), To: now, MinReports: a.MinReports})
		}
	}
	if len(scopes) == 0 {
		return nil
	}
	if w.source != source.Version {
		w.source = source.Version
		w.afterPolicy = ""
		w.afterRule = 0
	}
	page, err := w.Store.StagingCandidates(ctx, source.Version, scopes, w.afterPolicy, w.afterRule, 16)
	if err != nil {
		return err
	}
	if len(page) == 0 {
		w.afterPolicy = ""
		w.afterRule = 0
		return nil
	}
	for _, candidate := range page {
		p, ok := targets[candidate.PolicyName]
		if !ok {
			return errors.New("staging worker: candidate outside source")
		}
		evaluation, err := w.Evaluate(ctx, p.spec, candidate.RuleID, candidate.PolicyName, source.Version, now)
		if err != nil {
			return err
		}
		w.afterPolicy, w.afterRule = candidate.PolicyName, candidate.RuleID
		if !evaluation.ThresholdMet {
			continue
		}
		action, err := w.Writer.Stage(ctx, source.Version, p.id, p.version, candidate.RuleID)
		if errors.Is(err, policy.ErrStagingNotEligible) {
			continue
		}
		if errors.Is(err, store.ErrStagingConflict) {
			return nil
		}
		if err != nil {
			return err
		}
		log.Printf("[INFO] rule-health: staging recorded action=%s source=%d bundle=%d rule=%d", action.ID, action.SourceBundle, action.BundleVersion, action.RuleID)
		_, err = w.Publish(ctx, action)
		return err
	}
	return nil
}

// Run checks immediately and then every ten seconds, without overlapping ticks.
// Publication is retried from the ledger; errors never trigger re-enforcement.
func (w *StagingWorker) Run(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		if err := w.Tick(ctx); err != nil && ctx.Err() == nil {
			log.Printf("[WARN] rule-health: automatic staging: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
