package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
)

// StagingScope is query scope, not approval authority. The worker constructs it
// from exact source versions; the writer separately checks all authority again.
type StagingScope struct {
	PolicyName string    `json:"policy_name"`
	RuleID     uint32    `json:"rule_id"`
	From       time.Time `json:"from_at"`
	To         time.Time `json:"to_at"`
	MinReports uint32    `json:"min_reports"`
}

type StagingCandidate struct {
	PolicyName string
	RuleID     uint32
	Reports    uint64
}

// StagingCandidates pages only first, single-rule FP reports in the exact
// source bundle and both configured windows. Keyset pagination permits progress
// past candidates whose FP share fails; a fixed top-N would starve later rules.
// Counts here prefilter work; the writer always re-queries current evidence.
func (s *Store) StagingCandidates(ctx context.Context, bundle uint64, scopes []StagingScope, afterPolicy string, afterRule uint32, limit int) ([]StagingCandidate, error) {
	if bundle == 0 || len(scopes) > 65536 || len(afterPolicy) > 55 || limit < 1 || limit > 64 {
		return nil, errors.New("store: invalid staging candidate page")
	}
	if len(scopes) == 0 {
		return nil, nil
	}
	normalized := append([]StagingScope(nil), scopes...)
	seen := make(map[string]map[uint32]bool)
	ceil := func(t time.Time) time.Time {
		return t.Add(time.Microsecond - time.Nanosecond).UTC().Truncate(time.Microsecond)
	}
	for i, q := range normalized {
		if q.PolicyName == "" || len(q.PolicyName) > 55 || q.RuleID == 0 || q.MinReports < 1 || q.MinReports > 1000000000 || q.From.IsZero() || !q.To.After(q.From) || q.To.Sub(q.From) > 24*time.Hour {
			return nil, errors.New("store: invalid staging candidate scope")
		}
		if seen[q.PolicyName] == nil {
			seen[q.PolicyName] = make(map[uint32]bool)
		}
		if seen[q.PolicyName][q.RuleID] || len(seen[q.PolicyName]) >= 16 || len(seen) > 4096 {
			return nil, errors.New("store: duplicate or excessive candidate scope")
		}
		seen[q.PolicyName][q.RuleID] = true
		normalized[i].From, normalized[i].To = ceil(q.From), ceil(q.To)
	}
	raw, err := json.Marshal(normalized)
	if err != nil {
		return nil, fmt.Errorf("store: candidate scope JSON: %w", err)
	}
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	rows, err := s.pool.Query(bounded, `SELECT q.policy_name,q.rule_id,count(*) FROM
  jsonb_to_recordset($1::jsonb) AS q(policy_name text,rule_id bigint,from_at timestamptz,to_at timestamptz,min_reports bigint)
  JOIN rule_annotation_context c ON c.report_policy_id=q.policy_name AND c.report_rule_ids=ARRAY[q.rule_id]::bigint[]
  JOIN event_annotations a ON a.block_id=c.block_id
  WHERE c.report_bundle_version=$2::numeric
   AND c.report_event_at>=q.from_at AND c.report_event_at<q.to_at
   AND c.first_reported_at>=q.from_at AND c.first_reported_at<q.to_at
   AND (q.policy_name,q.rule_id)>($3::text,$4::bigint)
  GROUP BY q.policy_name,q.rule_id,q.min_reports HAVING count(*)>=q.min_reports
  ORDER BY q.policy_name,q.rule_id LIMIT $5`, raw, strconv.FormatUint(bundle, 10), afterPolicy, int64(afterRule), limit)
	if err != nil {
		return nil, fmt.Errorf("store: staging candidates: %w", err)
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (StagingCandidate, error) {
		var c StagingCandidate
		err := r.Scan(&c.PolicyName, &c.RuleID, &c.Reports)
		return c, err
	})
	if err != nil {
		return nil, fmt.Errorf("store: staging candidate rows: %w", err)
	}
	return out, nil
}
