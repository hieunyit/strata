package ingest

import (
	"context"
	"fmt"
	"sort"
	"time"
)

// PolicyRequests: the requests of one policy on one node over one interval
// (RV-N-01), and of them the ones not fully inspected, by why.
type PolicyRequests struct {
	Time        time.Time
	NodeID      string
	PolicyID    string // "": a name the node's bundle does not have
	Requests    uint64
	Partial     uint64 // the CPU budget ran out
	BodySkipped uint64 // the body, or part of it, was not inspected
	Error       uint64 // another engine error
	Degraded    uint64 // run degraded by the circuit breaker
}

// PolicyInspection: one policy's requests over the window and the share not
// fully inspected (Overview).
type PolicyInspection struct {
	PolicyID     string  `json:"policy_id"`
	Requests     uint64  `json:"requests"`
	NotInspected uint64  `json:"not_inspected"` // partial + body_skipped + error
	Partial      uint64  `json:"partial"`
	BodySkipped  uint64  `json:"body_skipped"`
	Error        uint64  `json:"error"`
	Degraded     uint64  `json:"degraded"`
	Share        float64 `json:"share"` // not_inspected / requests
}

func (p *PolicyInspection) finish() {
	p.NotInspected = p.Partial + p.BodySkipped + p.Error
	if p.Requests > 0 {
		p.Share = float64(p.NotInspected) / float64(p.Requests)
	}
}

const policyRequestsTable = "policy_requests"

// EnsurePolicyRequests creates the policy_requests table (schema.sql only
// runs when ClickHouse creates its volume) and gives it the TTL of days
// (<= 0: as created).
func (s *ClickHouseStore) EnsurePolicyRequests(ctx context.Context, days int) error {
	if err := s.conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS `+policyRequestsTable+` (
		timestamp DateTime64(3, 'UTC') CODEC(DoubleDelta, ZSTD(1)),
		node_id LowCardinality(String), policy_id LowCardinality(String),
		requests UInt64 CODEC(T64, ZSTD(1)), partial UInt64 CODEC(T64, ZSTD(1)),
		body_skipped UInt64 CODEC(T64, ZSTD(1)), error UInt64 CODEC(T64, ZSTD(1)),
		degraded UInt64 CODEC(T64, ZSTD(1)))
		ENGINE = MergeTree PARTITION BY toYYYYMMDD(timestamp) ORDER BY (policy_id, timestamp)
		TTL timestamp + INTERVAL 90 DAY`); err != nil {
		return fmt.Errorf("creating %s: %w", policyRequestsTable, err)
	}
	if days > 0 {
		if err := s.conn.Exec(ctx, fmt.Sprintf("ALTER TABLE %s MODIFY TTL timestamp + INTERVAL %d DAY", policyRequestsTable, days)); err != nil {
			return fmt.Errorf("setting the %s TTL: %w", policyRequestsTable, err)
		}
	}
	return nil
}

// SavePolicyRequests appends rows to policy_requests.
func (s *ClickHouseStore) SavePolicyRequests(ctx context.Context, rows []PolicyRequests) error {
	if len(rows) == 0 {
		return nil
	}
	b, err := s.conn.PrepareBatch(ctx, "INSERT INTO "+policyRequestsTable+
		" (timestamp, node_id, policy_id, requests, partial, body_skipped, error, degraded)")
	if err != nil {
		return fmt.Errorf("policy requests batch: %w", err)
	}
	for _, r := range rows {
		if err := b.Append(r.Time, r.NodeID, r.PolicyID, r.Requests, r.Partial, r.BodySkipped, r.Error, r.Degraded); err != nil {
			return fmt.Errorf("policy requests append: %w", err)
		}
	}
	if err := b.Send(); err != nil {
		return fmt.Errorf("policy requests send: %w", err)
	}
	return nil
}

// policyInspection sums policy_requests over the filter's window, the
// policies with the most requests first.
func (s *ClickHouseStore) policyInspection(ctx context.Context, f OverviewFilter) ([]PolicyInspection, error) {
	where, args := "timestamp >= ? AND timestamp < ?", []any{f.From, f.To}
	if f.PolicyID != "" {
		where += " AND policy_id = ?"
		args = append(args, f.PolicyID)
	}
	q := fmt.Sprintf(`SELECT policy_id, sum(requests) AS n, sum(partial), sum(body_skipped), sum(error), sum(degraded)
		FROM %s WHERE %s GROUP BY policy_id ORDER BY n DESC, policy_id LIMIT %d`, policyRequestsTable, where, TopN)
	out := []PolicyInspection{}
	err := s.collect(ctx, q, args, func(sc func(...any) error) error {
		var p PolicyInspection
		if err := sc(&p.PolicyID, &p.Requests, &p.Partial, &p.BodySkipped, &p.Error, &p.Degraded); err != nil {
			return err
		}
		p.finish()
		out = append(out, p)
		return nil
	})
	if err != nil && isUnknownTable(err) {
		return out, nil // a control plane that never created it
	}
	return out, err
}

// SavePolicyRequests keeps rows in memory.
func (m *MockEventStore) SavePolicyRequests(_ context.Context, rows []PolicyRequests) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.policyRequests = append(m.policyRequests, rows...)
	return nil
}

// PolicyRequestRows: what SavePolicyRequests kept.
func (m *MockEventStore) PolicyRequestRows() []PolicyRequests {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]PolicyRequests(nil), m.policyRequests...)
}

func (m *MockEventStore) policyInspection(f OverviewFilter) []PolicyInspection {
	by := map[string]*PolicyInspection{}
	for _, r := range m.policyRequests {
		if r.Time.Before(f.From) || !r.Time.Before(f.To) || (f.PolicyID != "" && r.PolicyID != f.PolicyID) {
			continue
		}
		p := by[r.PolicyID]
		if p == nil {
			p = &PolicyInspection{PolicyID: r.PolicyID}
			by[r.PolicyID] = p
		}
		p.Requests += r.Requests
		p.Partial += r.Partial
		p.BodySkipped += r.BodySkipped
		p.Error += r.Error
		p.Degraded += r.Degraded
	}
	out := []PolicyInspection{}
	for _, p := range by {
		p.finish()
		out = append(out, *p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Requests != out[j].Requests {
			return out[i].Requests > out[j].Requests
		}
		return out[i].PolicyID < out[j].PolicyID
	})
	if len(out) > TopN {
		out = out[:TopN]
	}
	return out
}

// requestsCounted sums the requests the nodes counted in [from, to)
// (W20-F-01); 0 without the table.
func (s *ClickHouseStore) requestsCounted(ctx context.Context, from, to time.Time, policyID string) (uint64, error) {
	where, args := "timestamp >= ? AND timestamp < ?", []any{from, to}
	if policyID != "" {
		where += " AND policy_id = ?"
		args = append(args, policyID)
	}
	var n uint64
	err := s.conn.QueryRow(ctx, "SELECT sum(requests) FROM "+policyRequestsTable+" WHERE "+where, args...).Scan(&n)
	if err != nil && isUnknownTable(err) {
		return 0, nil
	}
	return n, err
}
