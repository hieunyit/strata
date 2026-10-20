package ingest

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// W20-F-01: engine time of the inspected requests, from the nodes'
// heartbeats (the modules' histogram, summed over the workers): one row per
// node and interval, the buckets' increase over it.

// EngineBucketsUS are the upper bounds of the engine time buckets, in
// microseconds (the module's histogram; the last bucket, past 10 ms, has
// none).
var EngineBucketsUS = []float64{50, 100, 200, 500, 1000, 2000, 5000, 10000}

const engineTimeTable = "engine_time"

// EngineTime is the engine time of one node over one interval.
type EngineTime struct {
	Time    time.Time
	NodeID  string
	Buckets []uint64 // per bucket, not cumulative; len(EngineBucketsUS)+1
	Nanos   uint64
}

// EngineLatency of a window: requests timed, the mean, and quantiles as
// the upper bound of the bucket holding them (-1: past the last bound).
type EngineLatency struct {
	Requests uint64  `json:"requests"`
	MeanUS   float64 `json:"mean_us"`
	P50US    float64 `json:"p50_us"`
	P95US    float64 `json:"p95_us"`
	P99US    float64 `json:"p99_us"`
}

// latencyOf reads the quantiles from summed buckets; nil without requests.
func latencyOf(buckets []uint64, nanos uint64) *EngineLatency {
	var n uint64
	for _, b := range buckets {
		n += b
	}
	if n == 0 {
		return nil
	}
	q := func(p float64) float64 {
		target := uint64(float64(n)*p + 0.5)
		if target == 0 {
			target = 1
		}
		var c uint64
		for i, b := range buckets {
			c += b
			if c >= target {
				if i < len(EngineBucketsUS) {
					return EngineBucketsUS[i]
				}
				return -1
			}
		}
		return -1
	}
	return &EngineLatency{Requests: n, MeanUS: float64(nanos) / float64(n) / 1000, P50US: q(0.5), P95US: q(0.95), P99US: q(0.99)}
}

// EnsureEngineTime creates the engine_time table (ClickHouse migration 6).
func (s *ClickHouseStore) EnsureEngineTime(ctx context.Context) error {
	if err := s.conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS `+engineTimeTable+` (
		timestamp DateTime64(3, 'UTC') CODEC(DoubleDelta, ZSTD(1)),
		node_id   LowCardinality(String),
		buckets   Array(UInt64),
		engine_ns UInt64)
		ENGINE = MergeTree PARTITION BY toYYYYMMDD(timestamp) ORDER BY (timestamp, node_id)
		TTL timestamp + INTERVAL 90 DAY`); err != nil {
		return fmt.Errorf("creating %s: %w", engineTimeTable, err)
	}
	return nil
}

// SaveEngineTime appends rows to engine_time.
func (s *ClickHouseStore) SaveEngineTime(ctx context.Context, rows []EngineTime) error {
	if len(rows) == 0 {
		return nil
	}
	b, err := s.conn.PrepareBatch(ctx, "INSERT INTO "+engineTimeTable+" (timestamp, node_id, buckets, engine_ns)")
	if err != nil {
		return fmt.Errorf("engine time batch: %w", err)
	}
	for _, r := range rows {
		if err := b.Append(r.Time, r.NodeID, r.Buckets, r.Nanos); err != nil {
			return fmt.Errorf("engine time append: %w", err)
		}
	}
	if err := b.Send(); err != nil {
		return fmt.Errorf("engine time send: %w", err)
	}
	return nil
}

// engineLatency over the window, every node and policy (the module counts
// per worker, not per policy); nil without data.
func (s *ClickHouseStore) engineLatency(ctx context.Context, from, to time.Time) (*EngineLatency, error) {
	var buckets []uint64
	var nanos uint64
	err := s.conn.QueryRow(ctx, "SELECT sumForEach(buckets), sum(engine_ns) FROM "+engineTimeTable+" WHERE timestamp >= ? AND timestamp < ?",
		from, to).Scan(&buckets, &nanos)
	if err != nil {
		if isUnknownTable(err) {
			return nil, nil // a control plane that never created it
		}
		return nil, err
	}
	return latencyOf(buckets, nanos), nil
}

// SaveEngineTime keeps rows in memory.
func (m *MockEventStore) SaveEngineTime(_ context.Context, rows []EngineTime) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.engineTime = append(m.engineTime, rows...)
	return nil
}

func (m *MockEventStore) engineLatency(from, to time.Time) *EngineLatency {
	sum := make([]uint64, len(EngineBucketsUS)+1)
	var nanos uint64
	for _, r := range m.engineTime {
		if r.Time.Before(from) || !r.Time.Before(to) {
			continue
		}
		for i, b := range r.Buckets {
			if i < len(sum) {
				sum[i] += b
			}
		}
		nanos += r.Nanos
	}
	return latencyOf(sum, nanos)
}

// EngineTimeRows returns the rows saved (tests).
func (m *MockEventStore) EngineTimeRows() []EngineTime {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]EngineTime(nil), m.engineTime...)
}

// isUnknownTable: the table is not there (ClickHouse code 60; the message
// changed across versions: UNKNOWN_TABLE, "Unknown table expression").
func isUnknownTable(err error) bool {
	if err == nil {
		return false
	}
	m := err.Error()
	return strings.Contains(m, "UNKNOWN_TABLE") || strings.Contains(m, "code: 60,") || strings.Contains(m, "Unknown table")
}
