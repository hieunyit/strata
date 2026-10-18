package ingest

import (
	"context"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
)

// RuleMatchCount counts deduplicated matched security events in one exact
// deployed bundle and policy. It is a denominator for staging evaluation,
// not an all-request traffic counter.
func (s *ClickHouseStore) RuleMatchCount(ctx context.Context, rule uint32, policy string, bundle uint64, from, to time.Time) (uint64, error) {
	if rule == 0 || policy == "" || len(policy) > 55 || bundle == 0 || from.IsZero() || !to.After(from) || to.Sub(from) > 24*time.Hour {
		return 0, fmt.Errorf("ingest: invalid rule match query")
	}
	q := fmt.Sprintf(`SELECT count() FROM %s FINAL
 WHERE policy_id=@policy AND policy_version=@bundle AND has(matched_rules,@rule)
 AND timestamp>=@from AND timestamp<@to
 SETTINGS max_execution_time=5, max_memory_usage=268435456`, s.tableName)
	var n uint64
	err := s.conn.QueryRow(ctx, q, clickhouse.Named("policy", policy), clickhouse.Named("bundle", bundle), clickhouse.Named("rule", rule), clickhouse.DateNamed("from", from.UTC(), clickhouse.NanoSeconds), clickhouse.DateNamed("to", to.UTC(), clickhouse.NanoSeconds)).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("ingest: count rule matches: %w", err)
	}
	return n, nil
}
