package ingest

import (
	"context"
	"fmt"
	"time"
)

// RuleTelemetry counts deduplicated events and sampled top-eight event costs.
// These costs are not an unbiased estimate over all traffic. Decimal strings
// preserve UInt128 sums, even when individual agent counters reach UInt64 max.
type RuleTelemetry struct {
	MatchedEvents uint64
	CostSamples   string
	CostTotalNS   string
	CostMeanNS    *float64
}

func (s *ClickHouseStore) RuleTelemetry(ctx context.Context, rule uint32, policy string, from, to time.Time) (RuleTelemetry, error) {
	var out RuleTelemetry
	if rule == 0 || from.IsZero() || !to.After(from) || to.Sub(from) > 24*time.Hour || len(policy) > 55 {
		return out, fmt.Errorf("ingest: invalid rule telemetry query")
	}
	q := fmt.Sprintf(`WITH
 arraySum(arrayMap((id,n) -> if(id = ?, toUInt128(n), toUInt128(0)), rule_costs.rule_id, rule_costs.samples)) AS cs,
 arraySum(arrayMap((id,n) -> if(id = ?, toUInt128(n), toUInt128(0)), rule_costs.rule_id, rule_costs.total_ns)) AS ns
 SELECT countIf(has(matched_rules, ?)), toString(sum(cs)), toString(sum(ns)),
 if(sum(cs) = 0, NULL, toFloat64(sum(ns)) / toFloat64(sum(cs)))
 FROM %s FINAL WHERE timestamp >= ? AND timestamp < ?`, s.tableName)
	args := []any{rule, rule, rule, from, to}
	if policy != "" {
		q += " AND policy_id = ?"
		args = append(args, policy)
	}
	q += " SETTINGS max_execution_time=5, max_memory_usage=268435456"
	if err := s.conn.QueryRow(ctx, q, args...).Scan(&out.MatchedEvents, &out.CostSamples, &out.CostTotalNS, &out.CostMeanNS); err != nil {
		return out, fmt.Errorf("ingest: aggregate rule telemetry: %w", err)
	}
	return out, nil
}
