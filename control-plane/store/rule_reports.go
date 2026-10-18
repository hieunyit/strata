package store

import (
	"context"
	"fmt"
	"strconv"
	"time"
)

// RuleFPReportCount reads evidence eligible for automated staging evaluation.
// Only first reports of single-rule events in the exact bundle/policy and both
// half-open time windows count. No evidence is inferred for old annotations.
// This is an input to evaluation, never authorization to change a policy.
func (s *Store) RuleFPReportCount(ctx context.Context, rule uint32, policy string, bundle uint64, eventFrom, eventTo, reportFrom, reportTo time.Time) (uint64, error) {
	validWindow := func(from, to time.Time) bool { return !from.IsZero() && to.After(from) && to.Sub(from) <= 24*time.Hour }
	if rule == 0 || policy == "" || len(policy) > 55 || bundle == 0 || !validWindow(eventFrom, eventTo) || !validWindow(reportFrom, reportTo) {
		return 0, fmt.Errorf("store: invalid rule FP report query")
	}
	ceil := func(t time.Time) time.Time {
		return t.Add(time.Microsecond - time.Nanosecond).Truncate(time.Microsecond)
	}
	var n uint64
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM rule_annotation_context c JOIN event_annotations a USING(block_id)
 WHERE c.report_policy_id=$1 AND c.report_bundle_version=$2::numeric
 AND c.report_rule_ids=ARRAY[$3]::bigint[]
 AND c.report_event_at >= $4 AND c.report_event_at < $5
 AND c.first_reported_at >= $6 AND c.first_reported_at < $7`, policy, strconv.FormatUint(bundle, 10), int64(rule), ceil(eventFrom), ceil(eventTo), ceil(reportFrom), ceil(reportTo)).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("store: count rule FP reports: %w", err)
	}
	return n, nil
}
