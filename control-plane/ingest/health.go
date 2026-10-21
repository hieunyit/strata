package ingest

import (
	"context"
	"time"
)

// DeliveryHealth reports only counts and server ingest times, never event input.
// A quiet stream has no observed delivery lag; it is not a measured zero.
type DeliveryHealth struct {
	ClockSkewEvents uint64
	ObservedAt      *time.Time
	MaxLagSeconds   *uint64
}

func (s *ClickHouseStore) DeliveryHealth(ctx context.Context) (DeliveryHealth, error) {
	where, args := appendEventScope(ctx, "timestamp >= now() - INTERVAL 1 DAY AND received_at >= now() - INTERVAL 5 MINUTE", nil)
	var skew uint64
	var at *time.Time
	var lag *uint64
	err := s.conn.QueryRow(ctx, `SELECT maxOrNull(received_at),maxOrNull(toUInt64(greatest(0,dateDiff('second',timestamp,received_at)))),countIf(timestamp>received_at+INTERVAL 1 MINUTE) FROM events WHERE `+where+` SETTINGS max_execution_time=2`, args...).Scan(&at, &lag, &skew)
	return DeliveryHealth{ObservedAt: at, MaxLagSeconds: lag, ClockSkewEvents: skew}, err
}

type InspectionHealth struct {
	Requests, NotInspected, BodySkipped, Breaker, Shadow uint64
	ObservedAt                                           *time.Time
	Scoped                                               bool
}

func (s *ClickHouseStore) InspectionHealth(ctx context.Context, now time.Time) (InspectionHealth, error) {
	out := InspectionHealth{Scoped: scopedEvents(ctx)}
	where, args := appendEventScope(ctx, "timestamp >= ? AND timestamp < ?", []any{now.Add(-15 * time.Minute), now})
	if err := s.conn.QueryRow(ctx, "SELECT uniqExactIf(block_id,action='shadow') FROM events WHERE "+where+" SETTINGS max_execution_time=2", args...).Scan(&out.Shadow); err != nil {
		return out, err
	}
	if out.Scoped {
		return out, nil
	}
	err := s.conn.QueryRow(ctx, `SELECT sum(req),sum(missed),sum(body),sum(breaker),minOrNull(last) FROM (
 SELECT sum(requests) req,sum(partial+body_skipped+error) missed,sum(body_skipped) body,sum(degraded) breaker,max(timestamp) last
 FROM policy_requests WHERE timestamp>=? AND timestamp<? GROUP BY node_id) SETTINGS max_execution_time=2`, now.Add(-15*time.Minute), now).Scan(&out.Requests, &out.NotInspected, &out.BodySkipped, &out.Breaker, &out.ObservedAt)
	return out, err
}

// ReadCHSchemaVersion is strictly read-only; unlike CHSchemaVersion it does not
// initialize the migration ledger. Doctor may use a read-only database account.
func (s *ClickHouseStore) ReadCHSchemaVersion(ctx context.Context) (uint32, error) {
	var version uint32
	err := s.conn.QueryRow(ctx, "SELECT toUInt32(max(version)) FROM "+migrationsTable).Scan(&version)
	return version, err
}
