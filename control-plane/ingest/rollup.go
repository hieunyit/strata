package ingest

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
)

// W20-G2-01: hourly statistics for the Overview and the map's long
// windows. The events table may hold an event twice until it merges (a
// batch resent after a timeout), so the hourly numbers are not counted as
// events arrive: a job (RollupStats) recomputes, from events FINAL (each
// event once), every hour that received events since its last run, and
// writes rows that replace the hour's previous ones (ReplacingMergeTree by
// computed_at). Counts are exact; distinct clients are a sketch
// (uniqCombined64(14), about 1% error), top clients the heaviest of each
// hour. The numbers lag the events by at most the job's interval.

// Tables of the rollup.
const (
	StatsHourTable    = "stats_hour_v1"
	StatsRulesTable   = "stats_rules_hour_v1"
	StatsRoutesTable  = "stats_routes_hour_v1"
	StatsClientsTable = "stats_clients_hour_v1"
	StatsGeoTable     = "stats_geo_hour_v1"
	statsMarksTable   = "stats_rollup_marks"
	statsRolledMark   = "stats_v1_received_at" // received_at the job has seen up to
	statsReadyMark    = "stats_v1_ready"       // the first (backfill) run is done
	// clients kept per (hour, policy, action)
	statsClientsPerHour = 100
)

// rollupOverlap: events whose received_at is up to this much before the
// last mark are looked at again (ingest may write them a little late).
const rollupOverlap = 2 * time.Minute

// EnsureStatsRollup creates the rollup tables and the received_at index of
// the events table (ClickHouse migration 5).
func (s *ClickHouseStore) EnsureStatsRollup(ctx context.Context) error {
	ver := "computed_at DateTime64(3, 'UTC')"
	eng := func(order string) string {
		return "ENGINE = ReplacingMergeTree(computed_at) PARTITION BY toYYYYMM(hour) ORDER BY (" + order + ")"
	}
	stmts := []string{
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
			hour      DateTime('UTC') CODEC(DoubleDelta, ZSTD(1)),
			policy_id LowCardinality(String),
			action    LowCardinality(String),
			events    UInt64,
			clients   AggregateFunction(uniqCombined64(14), String),
			nodes     AggregateFunction(uniqExact, String),
			%s
		) %s`, StatsHourTable, ver, eng("hour, policy_id, action")),
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
			hour      DateTime('UTC') CODEC(DoubleDelta, ZSTD(1)),
			policy_id LowCardinality(String),
			action    LowCardinality(String),
			rule_id   UInt32,
			events    UInt64,
			%s
		) %s`, StatsRulesTable, ver, eng("hour, policy_id, rule_id, action")),
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
			hour      DateTime('UTC') CODEC(DoubleDelta, ZSTD(1)),
			policy_id LowCardinality(String),
			action    LowCardinality(String),
			host      String,
			prefix    String,
			events    UInt64,
			%s
		) %s`, StatsRoutesTable, ver, eng("hour, policy_id, host, prefix, action")),
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
			hour      DateTime('UTC') CODEC(DoubleDelta, ZSTD(1)),
			policy_id LowCardinality(String),
			action    LowCardinality(String),
			client_ip String,
			events    UInt64,
			%s
		) %s`, StatsClientsTable, ver, eng("hour, policy_id, action, client_ip")),
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
			hour        DateTime('UTC') CODEC(DoubleDelta, ZSTD(1)),
			policy_id   LowCardinality(String),
			action      LowCardinality(String),
			attack_type LowCardinality(String),
			country_iso LowCardinality(String),
			asn         UInt32,
			as_org      String,
			events      UInt64,
			%s
		) %s`, StatsGeoTable, ver, eng("hour, policy_id, action, attack_type, country_iso, asn")),
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (name String, value DateTime64(3, 'UTC'), updated_at DateTime64(3, 'UTC'))
			ENGINE = ReplacingMergeTree(updated_at) ORDER BY name`, statsMarksTable),
		fmt.Sprintf(`ALTER TABLE %s ADD INDEX IF NOT EXISTS received_at_minmax received_at TYPE minmax GRANULARITY 1`, s.tableName),
	}
	for _, q := range stmts {
		if err := s.conn.Exec(ctx, q); err != nil {
			return fmt.Errorf("creating the statistics rollup: %w", err)
		}
	}
	return nil
}

func (s *ClickHouseStore) statsMark(ctx context.Context, name string) (time.Time, bool, error) {
	var v time.Time
	var n uint64
	err := s.conn.QueryRow(ctx, fmt.Sprintf("SELECT count(), max(value) FROM %s FINAL WHERE name = ?", statsMarksTable), name).Scan(&n, &v)
	return v, n > 0, err
}

func (s *ClickHouseStore) setStatsMark(ctx context.Context, name string, v time.Time) error {
	return s.conn.Exec(ctx, fmt.Sprintf("INSERT INTO %s (name, value, updated_at) VALUES (?, ?, now64(3))", statsMarksTable), name, v)
}

// StatsReady reports whether the rollup covers the stored events (its first
// run finished): until then the Overview reads the events table.
func (s *ClickHouseStore) StatsReady(ctx context.Context) (bool, error) {
	_, ok, err := s.statsMark(ctx, statsReadyMark)
	return ok, err
}

// RollupStats recomputes the hours that received events since the last
// run (all of them the first time, a day at a time) and returns how many.
// Safe to run again after a failure, or from two control planes at once:
// a recomputation replaces the hour's rows.
func (s *ClickHouseStore) RollupStats(ctx context.Context) (int, error) {
	ctx = clickhouse.Context(ctx, clickhouse.WithSettings(clickhouse.Settings{"max_execution_time": 600}))
	since, _, err := s.statsMark(ctx, statsRolledMark)
	if err != nil {
		return 0, fmt.Errorf("statistics rollup mark: %w", err)
	}
	if !since.IsZero() {
		since = since.Add(-rollupOverlap)
	}
	var hours []time.Time
	var seen time.Time
	rows, err := s.conn.Query(ctx, fmt.Sprintf(`SELECT toStartOfHour(timestamp) AS h, max(received_at)
		FROM %s WHERE received_at > ? GROUP BY h ORDER BY h`, s.tableName), since)
	if err != nil {
		return 0, fmt.Errorf("statistics rollup: hours to update: %w", err)
	}
	for rows.Next() {
		var h, r time.Time
		if err := rows.Scan(&h, &r); err != nil {
			rows.Close()
			return 0, err
		}
		hours = append(hours, h.UTC())
		if r.After(seen) {
			seen = r
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	// contiguous hours in one pass each, at most a day
	for i := 0; i < len(hours); {
		j := i + 1
		for j < len(hours) && hours[j].Equal(hours[j-1].Add(time.Hour)) && j-i < 24 {
			j++
		}
		if err := s.rollupRange(ctx, hours[i], hours[j-1].Add(time.Hour)); err != nil {
			return 0, err
		}
		i = j
	}
	if len(hours) > 0 {
		if err := s.setStatsMark(ctx, statsRolledMark, seen); err != nil {
			return 0, err
		}
	}
	if ready, err := s.StatsReady(ctx); err != nil {
		return 0, err
	} else if !ready {
		if err := s.setStatsMark(ctx, statsReadyMark, time.Now()); err != nil {
			return 0, err
		}
	}
	return len(hours), nil
}

// statsPrefix is PathPrefix in SQL: the path without the query, its first
// two segments.
const statsPrefix = `arrayStringConcat(arraySlice(splitByChar('/', path(concat('http://h', http_path))), 1, 3), '/')`

// rollupRange recomputes the hours of [from, to).
func (s *ClickHouseStore) rollupRange(ctx context.Context, from, to time.Time) error {
	src := fmt.Sprintf("FROM %s FINAL WHERE timestamp >= ? AND timestamp < ?", s.tableName)
	stmts := []string{
		fmt.Sprintf(`INSERT INTO %s SELECT toStartOfHour(timestamp) AS hour, policy_id, action, count(),
			uniqCombined64State(14)(client_ip), uniqExactState(node_id), now64(3) %s
			GROUP BY hour, policy_id, action`, StatsHourTable, src),
		fmt.Sprintf(`INSERT INTO %s SELECT toStartOfHour(timestamp) AS hour, policy_id, action, rule_id, count(), now64(3)
			FROM %s FINAL ARRAY JOIN arrayDistinct(matched_rules) AS rule_id WHERE timestamp >= ? AND timestamp < ?
			GROUP BY hour, policy_id, action, rule_id`, StatsRulesTable, s.tableName),
		fmt.Sprintf(`INSERT INTO %s SELECT toStartOfHour(timestamp) AS hour, policy_id, action, http_host, %s AS prefix, count(), now64(3) %s
			GROUP BY hour, policy_id, action, http_host, prefix`, StatsRoutesTable, statsPrefix, src),
		fmt.Sprintf(`INSERT INTO %s SELECT toStartOfHour(timestamp) AS hour, policy_id, action, client_ip, count() AS n, now64(3) %s
			GROUP BY hour, policy_id, action, client_ip ORDER BY n DESC, client_ip LIMIT %d BY hour, policy_id, action`,
			StatsClientsTable, src, statsClientsPerHour),
		fmt.Sprintf(`INSERT INTO %s SELECT toStartOfHour(timestamp) AS hour, policy_id, action, %s AS attack_type,
			%s AS country, %s AS asn_, any(%s), count(), now64(3) %s
			GROUP BY hour, policy_id, action, attack_type, country, asn_`,
			StatsGeoTable, AttackTypeSQL, geoCountrySQL, geoASNSQL, geoASOrgSQL, src),
	}
	for _, q := range stmts {
		if err := s.conn.Exec(ctx, q, from, to); err != nil {
			return fmt.Errorf("statistics rollup %s..%s: %w", from.Format(time.RFC3339), to.Format(time.RFC3339), err)
		}
	}
	return nil
}

// rolledWindow is the window the rollup answers for f: whole hours, From
// rounded down and To up.
func rolledWindow(from, to time.Time) (time.Time, time.Time) {
	f := from.UTC().Truncate(time.Hour)
	t := to.UTC().Truncate(time.Hour)
	if t.Before(to.UTC()) {
		t = t.Add(time.Hour)
	}
	return f, t
}

// overviewRolled is Overview from the rollup tables.
func (s *ClickHouseStore) overviewRolled(ctx context.Context, f OverviewFilter) (*Overview, error) {
	from, to := rolledWindow(f.From, f.To)
	where := "hour >= ? AND hour < ?"
	args := []any{from, to}
	if f.PolicyID != "" {
		where += " AND policy_id = ?"
		args = append(args, f.PolicyID)
	}
	o := &Overview{From: from, To: to, StepSecond: int64(f.Step / time.Second), Approximate: true}
	const sums = `sumIf(events, action = 'block'), sumIf(events, action = 'shadow'), sumIf(events, action NOT IN ('block', 'shadow')), sumIf(events, action = 'error')`
	t := &o.Totals
	q := fmt.Sprintf(`SELECT sum(events), %s, uniqCombined64Merge(14)(clients), uniqExactMerge(nodes), uniqExactIf(policy_id, events > 0)
		FROM %s FINAL WHERE %s`, sums, StatsHourTable, where)
	if err := s.conn.QueryRow(ctx, q, args...).Scan(&t.Events, &t.Block, &t.Shadow, &t.Other, &t.Error, &t.Clients, &t.Nodes, &t.Policies); err != nil {
		return nil, fmt.Errorf("overview totals: %w", err)
	}
	buckets := map[int64]Bucket{}
	q = fmt.Sprintf(`SELECT toStartOfInterval(hour, toIntervalSecond(%d), 'UTC') AS b, %s FROM %s FINAL WHERE %s GROUP BY b ORDER BY b`,
		int64(f.Step/time.Second), sums, StatsHourTable, where)
	if err := s.collect(ctx, q, args, func(sc func(...any) error) error {
		var start time.Time
		var b Bucket
		if err := sc(&start, &b.Block, &b.Shadow, &b.Other, &b.Error); err != nil {
			return err
		}
		buckets[start.Unix()] = b
		return nil
	}); err != nil {
		return nil, fmt.Errorf("overview series: %w", err)
	}
	rf := f
	rf.From, rf.To = from, to
	o.Series = fillSeries(rf, buckets)
	q = fmt.Sprintf(`SELECT rule_id, sum(events) AS n, sumIf(events, action = 'block'), sumIf(events, action = 'shadow')
		FROM %s FINAL WHERE %s GROUP BY rule_id ORDER BY n DESC, rule_id LIMIT %d`, StatsRulesTable, where, TopN)
	o.TopRules = []RuleCount{}
	if err := s.collect(ctx, q, args, func(sc func(...any) error) error {
		var r RuleCount
		if err := sc(&r.RuleID, &r.Events, &r.Block, &r.Shadow); err != nil {
			return err
		}
		o.TopRules = append(o.TopRules, r)
		return nil
	}); err != nil {
		return nil, fmt.Errorf("overview top rules: %w", err)
	}
	q = fmt.Sprintf(`SELECT policy_id, host, prefix, sum(events) AS n, sumIf(events, action = 'block'), sumIf(events, action = 'shadow'), sumIf(events, action = 'error')
		FROM %s FINAL WHERE %s GROUP BY policy_id, host, prefix ORDER BY n DESC, policy_id, host, prefix LIMIT %d`, StatsRoutesTable, where, TopN)
	o.TopRoutes = []RouteCount{}
	if err := s.collect(ctx, q, args, func(sc func(...any) error) error {
		var r RouteCount
		if err := sc(&r.PolicyID, &r.Host, &r.PathPrefix, &r.Events, &r.Block, &r.Shadow, &r.Error); err != nil {
			return err
		}
		o.TopRoutes = append(o.TopRoutes, r)
		return nil
	}); err != nil {
		return nil, fmt.Errorf("overview top routes: %w", err)
	}
	if f.Clients {
		q = fmt.Sprintf(`SELECT client_ip, sum(events) AS n, sumIf(events, action = 'block')
			FROM %s FINAL WHERE %s GROUP BY client_ip ORDER BY n DESC, client_ip LIMIT %d`, StatsClientsTable, where, TopN)
		o.TopClients = []ClientCount{}
		if err := s.collect(ctx, q, args, func(sc func(...any) error) error {
			var c ClientCount
			if err := sc(&c.ClientIP, &c.Events, &c.Block); err != nil {
				return err
			}
			o.TopClients = append(o.TopClients, c)
			return nil
		}); err != nil {
			return nil, fmt.Errorf("overview top clients: %w", err)
		}
	}
	var err error
	if o.Inspection, err = s.policyInspection(ctx, f); err != nil {
		return nil, fmt.Errorf("overview inspection: %w", err)
	}
	if o.Engine, err = s.engineLatency(ctx, from, to); err != nil {
		return nil, fmt.Errorf("overview engine time: %w", err)
	}
	if o.Totals.Requests, err = s.requestsCounted(ctx, from, to, f.PolicyID); err != nil {
		return nil, fmt.Errorf("overview requests: %w", err)
	}
	return o, nil
}

// geoRolledFor reports whether a geo read over f is served by the rollup:
// 6 hours and more, once it is ready (shorter windows keep the minute
// aggregates, which the live map reads).
func (s *ClickHouseStore) geoRolledFor(ctx context.Context, f GeoFilter) bool {
	if f.To.Sub(f.From) < 6*time.Hour {
		return false
	}
	ok, err := s.StatsReady(ctx)
	return err == nil && ok
}

// EnsureStatsTTL keeps the rollup tables months months (<= 0 leaves them),
// as the GeoIP aggregates (-geo-aggregates-months).
func (s *ClickHouseStore) EnsureStatsTTL(ctx context.Context, months int) error {
	if months <= 0 {
		return nil
	}
	for _, table := range []string{StatsHourTable, StatsRulesTable, StatsRoutesTable, StatsClientsTable, StatsGeoTable} {
		var create string
		if err := s.conn.QueryRow(ctx,
			"SELECT create_table_query FROM system.tables WHERE database = currentDatabase() AND name = ?",
			table).Scan(&create); err != nil {
			return fmt.Errorf("reading %s: %w", table, err)
		}
		if strings.Contains(create, fmt.Sprintf("TTL hour + toIntervalMonth(%d)", months)) {
			continue
		}
		if err := s.conn.Exec(ctx, fmt.Sprintf("ALTER TABLE %s MODIFY TTL hour + toIntervalMonth(%d)", table, months)); err != nil {
			return fmt.Errorf("setting the retention of %s: %w", table, err)
		}
	}
	return nil
}
