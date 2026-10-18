package rulehealth

import (
	"context"
	"time"

	"github.com/strata/strata/control-plane/policy"
)

// Observe supplies scoped durable counts to the restricted writer. A cached
// ThresholdMet boolean is not authority: the writer rechecks its captured
// delegation, scope, windows and exact arithmetic before signing anything.
func (s *Service) Observe(ctx context.Context, spec policy.Spec, rule uint32, name string, bundle uint64, now time.Time) (policy.StagingEvidence, error) {
	e, err := s.Evaluate(ctx, spec, rule, name, bundle, now)
	return policy.StagingEvidence{RuleID: e.RuleID, PolicyName: e.PolicyName, BundleVersion: e.BundleVersion, From: e.From, To: e.To, Matches: e.MatchedEvents, Reports: e.FPReports}, err
}
