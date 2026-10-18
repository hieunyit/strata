package rulehealth

import (
	"context"
	"fmt"
	"math/bits"
	"time"

	"github.com/strata/strata/control-plane/policy"
)

type MatchReader interface {
	RuleMatchCount(context.Context, uint32, string, uint64, time.Time, time.Time) (uint64, error)
}
type ReportReader interface {
	RuleFPReportCount(context.Context, uint32, string, uint64, time.Time, time.Time, time.Time, time.Time) (uint64, error)
}

// Evaluation is a read-only observation, never approval or deployment authority.
// A writer must separately verify the active approved policy, exact compiler
// inputs, managed rule membership and durable idempotency before acting.
type Evaluation struct {
	RuleID                   uint32
	PolicyName               string
	BundleVersion            uint64
	From, To                 time.Time
	MatchedEvents, FPReports uint64
	ThresholdMet             bool
}

// Evaluate checks one explicitly delegated rule against both durable stores.
// Disabled, shadow or non-allowlisted rules cause no I/O. It shares the health
// API's four slots and five-second total I/O budget; no callbacks or state writes.
func (s *Service) Evaluate(ctx context.Context, spec policy.Spec, rule uint32, name string, bundle uint64, now time.Time) (Evaluation, error) {
	out := Evaluation{RuleID: rule, PolicyName: name, BundleVersion: bundle, To: now.UTC()}
	if err := spec.Validate(); err != nil {
		return out, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if rule == 0 || bundle == 0 || !policy.NamePattern.MatchString(name) || now.IsZero() {
		return out, ErrInvalid
	}
	a := spec.AutoStaging
	if spec.Mode != "enforce" || a == nil || !a.Enabled {
		return out, nil
	}
	allowed := false
	for _, id := range a.RuleIDs {
		if id == rule {
			allowed = true
			break
		}
	}
	if !allowed {
		return out, nil
	}
	matches, ok := s.events.(MatchReader)
	if !ok || matches == nil {
		return out, ErrUnavailable
	}
	reports, ok := s.annotations.(ReportReader)
	if !ok || reports == nil {
		return out, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		return out, ErrBusy
	}
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out.From = out.To.Add(-time.Duration(a.WindowSeconds) * time.Second)
	var err error
	out.MatchedEvents, err = matches.RuleMatchCount(bounded, rule, name, bundle, out.From, out.To)
	if err != nil {
		return out, fmt.Errorf("rule evaluation matches: %w", err)
	}
	out.FPReports, err = reports.RuleFPReportCount(bounded, rule, name, bundle, out.From, out.To, out.From, out.To)
	if err != nil {
		return out, fmt.Errorf("rule evaluation reports: %w", err)
	}
	if err := bounded.Err(); err != nil {
		return out, err
	}
	if out.FPReports > out.MatchedEvents || out.MatchedEvents < uint64(a.MinMatches) || out.FPReports < uint64(a.MinReports) {
		return out, nil
	}
	// Compare exact 128-bit products: UInt64 counts can overflow multiplication
	// by 10000, and float rounding can authorize just below a threshold.
	fh, fl := bits.Mul64(out.FPReports, 10000)
	mh, ml := bits.Mul64(out.MatchedEvents, uint64(a.FPThresholdBPS))
	out.ThresholdMet = fh > mh || fh == mh && fl >= ml
	return out, nil
}
