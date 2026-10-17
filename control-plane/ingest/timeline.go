package ingest

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// TimelineBucket represents aggregated request verdicts and threats for a time slice.
type TimelineBucket struct {
	Timestamp   time.Time         `json:"timestamp"`
	Total       uint64            `json:"total"`
	Blocked     uint64            `json:"blocked"`
	Monitored   uint64            `json:"monitored"`
	Passed      uint64            `json:"passed"`
	Challenged  uint64            `json:"challenged,omitempty"`
	AttackTypes map[string]uint64 `json:"attack_types,omitempty"`
}

// TimelineFilter specifies filtering and interval granularity for timeline series.
type TimelineFilter struct {
	From       time.Time
	To         time.Time
	Step       time.Duration // 1m, 5m, 1h, 6h, 24h
	PolicyID   string
	CountryISO string
	ASN        uint32
	Action     string
}

// TimelineResponse contains interval slices over the requested observation window.
type TimelineResponse struct {
	From    time.Time        `json:"from"`
	To      time.Time        `json:"to"`
	Step    string           `json:"step"`
	Buckets []TimelineBucket `json:"buckets"`
}

// TimelineStore defines the interface for retrieving time-series analytics.
type TimelineStore interface {
	Timeline(ctx context.Context, f TimelineFilter) (*TimelineResponse, error)
}

// ValidTimelineStep ensures only supported aggregation steps are accepted.
func ValidTimelineStep(d time.Duration) bool {
	switch d {
	case time.Minute, 5 * time.Minute, time.Hour, 6 * time.Hour, 24 * time.Hour:
		return true
	default:
		return false
	}
}

// DefaultTimelineStep derives an appropriate time step given a time window.
func DefaultTimelineStep(span time.Duration) time.Duration {
	switch {
	case span <= 2*time.Hour:
		return time.Minute
	case span <= 12*time.Hour:
		return 5 * time.Minute
	case span <= 7*24*time.Hour:
		return time.Hour
	case span <= 30*24*time.Hour:
		return 6 * time.Hour
	default:
		return 24 * time.Hour
	}
}

// Timeline executes an aggregated time-series query on ClickHouse events_geo_minute.
func (s *ClickHouseStore) Timeline(ctx context.Context, f TimelineFilter) (*TimelineResponse, error) {
	if f.From.IsZero() {
		f.From = time.Now().UTC().Add(-24 * time.Hour)
	}
	if f.To.IsZero() {
		f.To = time.Now().UTC()
	}
	if f.Step <= 0 {
		f.Step = DefaultTimelineStep(f.To.Sub(f.From))
	}

	stepMinutes := int(f.Step.Minutes())
	if stepMinutes <= 0 {
		stepMinutes = 60
	}

	where := []string{"minute >= ? AND minute <= ?"}
	args := []any{f.From, f.To}

	if f.PolicyID != "" {
		where = append(where, "policy_id = ?")
		args = append(args, f.PolicyID)
	}
	if f.CountryISO != "" {
		where = append(where, "country_iso = ?")
		args = append(args, f.CountryISO)
	}
	if f.ASN > 0 {
		where = append(where, "asn = ?")
		args = append(args, f.ASN)
	}
	if f.Action != "" {
		where = append(where, "action = ?")
		args = append(args, f.Action)
	}

	whereSQL := strings.Join(where, " AND ")

	query := fmt.Sprintf(`SELECT
		toStartOfInterval(minute, INTERVAL %d MINUTE) AS bucket,
		attack_type,
		sum(count) AS total_count,
		sum(blocked_count) AS blk_count,
		sum(if(action = 'monitor', count, 0)) AS mon_count,
		sum(if(action = 'pass', count, 0)) AS pass_count,
		sum(if(action = 'challenge', count, 0)) AS chal_count
	FROM %s
	WHERE %s
	GROUP BY bucket, attack_type
	ORDER BY bucket ASC`, stepMinutes, geoMinuteTable, whereSQL)

	rows, err := s.conn.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("querying timeline from %s: %w", geoMinuteTable, err)
	}
	defer rows.Close()

	bucketMap := make(map[time.Time]*TimelineBucket)
	for rows.Next() {
		var (
			bucketTime time.Time
			attackType string
			total      uint64
			blocked    uint64
			monitored  uint64
			passed     uint64
			challenged uint64
		)
		if err := rows.Scan(&bucketTime, &attackType, &total, &blocked, &monitored, &passed, &challenged); err != nil {
			return nil, fmt.Errorf("scanning timeline row: %w", err)
		}

		b, exists := bucketMap[bucketTime]
		if !exists {
			b = &TimelineBucket{
				Timestamp:   bucketTime,
				AttackTypes: make(map[string]uint64),
			}
			bucketMap[bucketTime] = b
		}
		b.Total += total
		b.Blocked += blocked
		b.Monitored += monitored
		b.Passed += passed
		b.Challenged += challenged
		if attackType != "" && attackType != "anomaly" {
			b.AttackTypes[attackType] += total
		}
	}

	buckets := make([]TimelineBucket, 0, len(bucketMap))
	for _, b := range bucketMap {
		buckets = append(buckets, *b)
	}
	sort.Slice(buckets, func(i, j int) bool {
		return buckets[i].Timestamp.Before(buckets[j].Timestamp)
	})

	return &TimelineResponse{
		From:    f.From,
		To:      f.To,
		Step:    f.Step.String(),
		Buckets: buckets,
	}, nil
}

// Timeline aggregates in-memory events on MockEventStore for tests.
func (m *MockEventStore) Timeline(_ context.Context, f TimelineFilter) (*TimelineResponse, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if f.From.IsZero() {
		f.From = time.Now().UTC().Add(-24 * time.Hour)
	}
	if f.To.IsZero() {
		f.To = time.Now().UTC()
	}
	if f.Step <= 0 {
		f.Step = DefaultTimelineStep(f.To.Sub(f.From))
	}

	bucketMap := make(map[time.Time]*TimelineBucket)

	for _, e := range m.eventsList {
		if !f.From.IsZero() && e.Timestamp.Before(f.From) {
			continue
		}
		if !f.To.IsZero() && e.Timestamp.After(f.To) {
			continue
		}
		if f.PolicyID != "" && e.PolicyID != f.PolicyID {
			continue
		}
		if f.CountryISO != "" && e.CountryISO != f.CountryISO {
			continue
		}
		if f.ASN > 0 && e.ASN != f.ASN {
			continue
		}
		if f.Action != "" && e.Action != f.Action {
			continue
		}

		// Floor timestamp to step
		bucketTime := e.Timestamp.Truncate(f.Step)
		b, exists := bucketMap[bucketTime]
		if !exists {
			b = &TimelineBucket{
				Timestamp:   bucketTime,
				AttackTypes: make(map[string]uint64),
			}
			bucketMap[bucketTime] = b
		}
		b.Total++
		switch e.Action {
		case "block":
			b.Blocked++
		case "monitor":
			b.Monitored++
		case "challenge":
			b.Challenged++
		default:
			b.Passed++
		}

		if e.ScoreSQLi > 0 {
			b.AttackTypes["sqli"]++
		}
		if e.ScoreXSS > 0 {
			b.AttackTypes["xss"]++
		}
		if e.ScoreProtocol > 0 {
			b.AttackTypes["protocol"]++
		}
		if e.ScoreAnomaly > 0 {
			b.AttackTypes["anomaly"]++
		}
	}

	buckets := make([]TimelineBucket, 0, len(bucketMap))
	for _, b := range bucketMap {
		buckets = append(buckets, *b)
	}
	sort.Slice(buckets, func(i, j int) bool {
		return buckets[i].Timestamp.Before(buckets[j].Timestamp)
	})

	return &TimelineResponse{
		From:    f.From,
		To:      f.To,
		Step:    f.Step.String(),
		Buckets: buckets,
	}, nil
}
