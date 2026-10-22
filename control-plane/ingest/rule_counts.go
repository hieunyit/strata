package ingest

import (
	"context"
	"fmt"
	"time"
)

// RuleCountStore is implemented by the event stores that count the events
// of each rule (RS-4b: events of a rule set over the last day, on the
// policy editor).
type RuleCountStore interface {
	// RuleCounts: events of [from, to) that matched each rule (an event
	// counts once per distinct rule), of policy only unless "".
	RuleCounts(ctx context.Context, policy string, from, to time.Time) (map[uint32]uint64, error)
}

// RuleCounts reads the hourly rollup once it covers the events (whole
// hours: the window is widened to them), the events table otherwise and
// for callers that see part of the events only.
func (s *ClickHouseStore) RuleCounts(ctx context.Context, policy string, from, to time.Time) (map[uint32]uint64, error) {
	var where, q string
	var args []any
	if ready, err := s.StatsReady(ctx); err == nil && ready && !scopedEvents(ctx) {
		f, t := rolledWindow(from, to)
		where, args = "hour >= ? AND hour < ?", []any{f, t}
		if policy != "" {
			where += " AND policy_id = ?"
			args = append(args, policy)
		}
		q = fmt.Sprintf(`SELECT rule_id, sum(events) FROM %s FINAL WHERE %s GROUP BY rule_id`, StatsRulesTable, where)
	} else {
		where, args = "timestamp >= ? AND timestamp < ?", []any{from, to}
		if policy != "" {
			where += " AND policy_id = ?"
			args = append(args, policy)
		}
		where, args = appendEventScope(ctx, where, args)
		q = fmt.Sprintf(`SELECT rule_id, count() FROM %s FINAL ARRAY JOIN arrayDistinct(matched_rules) AS rule_id WHERE %s GROUP BY rule_id`, s.tableName, where)
	}
	out := map[uint32]uint64{}
	if err := s.collect(ctx, q, args, func(sc func(...any) error) error {
		var id uint32
		var n uint64
		if err := sc(&id, &n); err != nil {
			return err
		}
		out[id] = n
		return nil
	}); err != nil {
		return nil, fmt.Errorf("rule counts: %w", err)
	}
	return out, nil
}

// RuleCounts counts the in-memory events the same way.
func (m *MockEventStore) RuleCounts(ctx context.Context, policy string, from, to time.Time) (map[uint32]uint64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := map[uint32]uint64{}
	for _, e := range m.eventsList {
		if !eventAllowed(ctx, e) || e.Timestamp.Before(from) || !e.Timestamp.Before(to) || policy != "" && e.PolicyID != policy {
			continue
		}
		seen := map[uint32]bool{}
		for _, id := range e.MatchedRules {
			if !seen[id] {
				seen[id] = true
				out[id]++
			}
		}
	}
	return out, nil
}
