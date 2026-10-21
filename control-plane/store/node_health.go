package store

import (
	"context"
	"encoding/json"
	"time"
)

// NodeTelemetry contains only diagnostic counters. It grants no authority and
// never includes addresses, request input, logs, keys or arbitrary agent text.
type NodeTelemetry struct {
	MetricsAvailable bool            `json:"metrics_available"`
	Requests         uint64          `json:"requests"`
	Blocked          uint64          `json:"blocked"`
	FailOpen         uint64          `json:"fail_open"`
	DroppedEvents    uint64          `json:"dropped_events"`
	AgentStartedMs   uint64          `json:"agent_started_ms"`
	MetricsCreatedMs uint64          `json:"metrics_created_ms"`
	Spool            *SpoolTelemetry `json:"spool,omitempty"`
}
type SpoolTelemetry struct {
	Bytes          uint64 `json:"bytes"`
	LimitBytes     uint64 `json:"limit_bytes"`
	PendingBatches uint64 `json:"pending_batches"`
	DroppedEvents  uint64 `json:"dropped_events"`
}

func (s *Store) RecordNodeTelemetry(ctx context.Context, id string, telemetry NodeTelemetry, at time.Time) error {
	raw, err := json.Marshal(telemetry)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, "UPDATE nodes SET health=$2,health_at=$3 WHERE id=$1 AND revoked_at IS NULL", id, raw, at.UTC())
	return err
}

type HealthNode struct {
	ID           string
	Connected    bool
	LastSeen     *time.Time
	Actual       *int64
	Desired      *int64
	CertNotAfter *time.Time
	Telemetry    *NodeTelemetry
	TelemetryAt  *time.Time
}

func (s *Store) HealthNodes(ctx context.Context, ids []string) ([]HealthNode, bool, error) {
	rows, err := s.pool.Query(ctx, `SELECT id,connected,last_seen_at,bundle_version,desired_bundle_version,cert_not_after,health,health_at FROM nodes WHERE revoked_at IS NULL AND ($1::text[] IS NULL OR id=ANY($1)) ORDER BY id LIMIT 1001`, ids)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	out := []HealthNode{}
	for rows.Next() {
		var n HealthNode
		var raw []byte
		if err := rows.Scan(&n.ID, &n.Connected, &n.LastSeen, &n.Actual, &n.Desired, &n.CertNotAfter, &raw, &n.TelemetryAt); err != nil {
			return nil, false, err
		}
		if len(raw) > 0 {
			var telemetry NodeTelemetry
			if err := json.Unmarshal(raw, &telemetry); err != nil {
				return nil, false, err
			}
			n.Telemetry = &telemetry
		}
		out = append(out, n)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	truncated := len(out) > 1000
	if truncated {
		out = out[:1000]
	}
	return out, truncated, nil
}
func (s *Store) FailedOperationsSince(ctx context.Context, since time.Time, policies []string) (uint64, error) {
	var count uint64
	err := s.pool.QueryRow(ctx, "SELECT count(*) FROM operations WHERE state='FAILED' AND finished_at>=$1 AND ($2::text[] IS NULL OR policy_id=ANY($2))", since, policies).Scan(&count)
	return count, err
}
