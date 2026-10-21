package ingest

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
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
 arraySum(arrayMap((id,n) -> if(id = @rule, toUInt128(n), toUInt128(0)), rule_costs.rule_id, rule_costs.samples)) AS cs,
 arraySum(arrayMap((id,n) -> if(id = @rule, toUInt128(n), toUInt128(0)), rule_costs.rule_id, rule_costs.total_ns)) AS ns
 SELECT countIf(has(matched_rules, @rule)), toString(sum(cs)), toString(sum(ns)),
 if(sum(cs) = 0, NULL, toFloat64(sum(ns)) / toFloat64(sum(cs)))
 FROM %s FINAL WHERE timestamp >= @from AND timestamp < @to`, s.tableName)
	// Ordinary time.Time binding uses seconds in this driver. Preserve the
	// caller's boundary precision when comparing DateTime64(3) event rows.
	args := []any{clickhouse.Named("rule", rule), clickhouse.DateNamed("from", from.UTC(), clickhouse.NanoSeconds), clickhouse.DateNamed("to", to.UTC(), clickhouse.NanoSeconds)}
	if policy != "" {
		q += " AND policy_id = @policy"
		args = append(args, clickhouse.Named("policy", policy))
	}
	scope, scopeArgs := eventScopeSQL(ctx)
	for i, value := range scopeArgs {
		name := fmt.Sprintf("rule_scope_%d", i)
		scope = strings.Replace(scope, "?", "@"+name, 1)
		args = append(args, clickhouse.Named(name, value))
	}
	q += " AND (" + scope + ")"
	q += " SETTINGS max_execution_time=5, max_memory_usage=268435456"
	if err := s.conn.QueryRow(ctx, q, args...).Scan(&out.MatchedEvents, &out.CostSamples, &out.CostTotalNS, &out.CostMeanNS); err != nil {
		return out, fmt.Errorf("ingest: aggregate rule telemetry: %w", err)
	}
	return out, nil
}
