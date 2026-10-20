package policy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/bits"
	"time"

	"github.com/strata/strata/agent/pkg/bundlefmt"
	"github.com/strata/strata/control-plane/store"
)

var ErrStagingNotEligible = errors.New("staging: source, delegation or evidence not eligible")

type StagingStore interface {
	StagingReader
	WithBundleLock(context.Context, func(uint64) error) error
	LatestBundle(context.Context) (store.Bundle, error)
	BundlePolicies(context.Context, uint64) ([]store.Policy, error)
	StagingSourceReady(context.Context, uint64) (bool, error)
	RecordStagingBundle(context.Context, store.Bundle, store.Bundle, store.StagingAction, store.Audit) (store.StagingAction, error)
}

type StagingEvidence struct {
	RuleID           uint32
	PolicyName       string
	BundleVersion    uint64
	From, To         time.Time
	Matches, Reports uint64
}

// StagingDeployer is a separate restricted writer. It cannot edit a spec,
// remove an overlay, approve anything or invoke the ordinary deploy gate.
// A successful Stage records durable publication intent, not runtime ACTIVE.
type StagingDeployer struct {
	Store        StagingStore
	Compiler     *Compiler
	Objects      Objects
	PubKey       []byte
	VerifySource func(context.Context, store.Bundle) error
	Observe      func(context.Context, Spec, uint32, string, uint64, time.Time) (StagingEvidence, error)
	Now          func() time.Time
}

func (d *StagingDeployer) Stage(ctx context.Context, sourceVersion uint64, policyID string, version int, rule uint32) (store.StagingAction, error) {
	if d.Store == nil || d.Compiler == nil || d.Objects == nil || d.VerifySource == nil || d.Observe == nil {
		return store.StagingAction{}, errors.New("staging: writer not configured")
	}
	if sourceVersion == 0 || policyID == "" || version < 1 || rule == 0 {
		return store.StagingAction{}, ErrStagingNotEligible
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	var out store.StagingAction
	err := d.Store.WithBundleLock(ctx, func(next uint64) error {
		source, err := d.Store.LatestBundle(ctx)
		if err != nil {
			return err
		}
		if source.Version != sourceVersion || next != source.Version+1 {
			return store.ErrStagingConflict
		}
		ready, err := d.Store.StagingSourceReady(ctx, source.Version)
		if err != nil {
			return err
		}
		if !ready {
			return ErrStagingNotEligible
		}
		ps, err := d.Store.BundlePolicies(ctx, source.Version)
		if err != nil {
			return err
		}
		named := make([]Named, 0, len(ps))
		var target *Named
		for _, p := range ps {
			spec, err := Parse(p.Spec)
			if err != nil {
				return fmt.Errorf("staging: policy %s v%d: %w", p.ID, p.CurrentVersion, err)
			}
			named = append(named, Named{ResourceID: p.ID, Version: p.CurrentVersion, Name: p.Name, Spec: spec})
		}
		for i := range named {
			if named[i].ResourceID == policyID && named[i].Version == version {
				target = &named[i]
				break
			}
		}
		if target == nil || target.Spec.Mode != "enforce" || target.Spec.AutoStaging == nil || !target.Spec.AutoStaging.Enabled {
			return ErrStagingNotEligible
		}
		delegation := *target.Spec.AutoStaging
		allowed := false
		for _, id := range delegation.RuleIDs {
			if id == rule {
				allowed = true
				break
			}
		}
		if !allowed {
			return ErrStagingNotEligible
		}
		if err = d.VerifySource(ctx, source); err != nil {
			return err
		}
		original, err := d.Objects.Get(ctx, source.ObjectKey)
		if err != nil {
			return err
		}
		header, err := bundlefmt.Verify(original, d.PubKey)
		if err != nil {
			return fmt.Errorf("staging: source signature: %w", err)
		}
		sum := sha256.Sum256(original)
		if header.Version != source.Version || int(header.Policies) != len(named) || int64(len(original)) != source.SizeBytes || !bytes.Equal(sum[:], source.SHA256) {
			return ErrStagingSourceMismatch
		}
		compiler := *d.Compiler
		compiler.StagingStore = d.Store
		prepared, err := compiler.Prepare(ctx, named)
		if err != nil {
			return err
		}
		defer prepared.Close()
		if prepared.Digest != source.InputDigest {
			return ErrStagingSourceMismatch
		}
		for _, id := range prepared.compiler.StagedRules[target.Name] {
			if id == rule {
				return ErrStagingNotEligible
			}
		}
		now := time.Now().UTC().Truncate(time.Microsecond)
		if d.Now != nil {
			now = d.Now().UTC().Truncate(time.Microsecond)
		}
		evidence, err := d.Observe(ctx, target.Spec, rule, target.Name, source.Version, now)
		if err != nil {
			return err
		}
		from := now.Add(-time.Duration(delegation.WindowSeconds) * time.Second)
		if evidence.RuleID != rule || evidence.PolicyName != target.Name || evidence.BundleVersion != source.Version || !evidence.From.Equal(from) || !evidence.To.Equal(now) ||
			evidence.Matches < uint64(delegation.MinMatches) || evidence.Reports < uint64(delegation.MinReports) || evidence.Reports > evidence.Matches {
			return ErrStagingNotEligible
		}
		fh, fl := bits.Mul64(evidence.Reports, 10000)
		mh, ml := bits.Mul64(evidence.Matches, uint64(delegation.FPThresholdBPS))
		if fh < mh || fh == mh && fl < ml {
			return ErrStagingNotEligible
		}
		if err = prepared.addStagedRules(source.InputDigest, target.Name, []uint32{rule}); err != nil {
			return err
		}
		data, err := prepared.Build(ctx, next)
		if err != nil {
			return err
		}
		header, err = bundlefmt.Verify(data, d.PubKey)
		if err != nil {
			return fmt.Errorf("staging: derived signature: %w", err)
		}
		if header.Version != next || int(header.Policies) != len(named) {
			return ErrStagingSourceMismatch
		}
		ready, err = d.Store.StagingSourceReady(ctx, source.Version)
		if err != nil {
			return err
		}
		if !ready {
			return ErrStagingNotEligible
		}
		sum = sha256.Sum256(data)
		key := ObjectKey(next)
		if err = d.Objects.Put(ctx, key, data, hex.EncodeToString(sum[:])); err != nil {
			return err
		}
		request, err := json.Marshal(struct {
			Source  uint64
			Policy  string
			Version int
			Rule    uint32
		}{source.Version, policyID, version, rule})
		if err != nil {
			return err
		}
		requestSum := sha256.Sum256(request)
		out, err = d.Store.RecordStagingBundle(ctx, source, store.Bundle{Version: next, InputDigest: prepared.Digest, RulesDigest: prepared.RulesDigest, SHA256: sum[:], ObjectKey: key, SizeBytes: int64(len(data)), Contents: source.Contents},
			store.StagingAction{ID: hex.EncodeToString(requestSum[:]), PolicyID: policyID, PolicyVersion: version, RuleID: rule, Matches: evidence.Matches, Reports: evidence.Reports, WindowFrom: from, WindowTo: now},
			store.Audit{Actor: "rule-health", Channel: "system", Action: "rule-staging:record", Resource: fmt.Sprintf("policies/%s/versions/%d/rules/%d", policyID, version, rule)})
		return err
	})
	return out, err
}
