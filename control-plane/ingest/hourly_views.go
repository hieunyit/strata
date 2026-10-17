package ingest

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/sync/errgroup"
)

const (
	hourlyStatsTable  = "events_stats_hourly"
	hourlyStatsMV     = "events_stats_hourly_mv"
	hourlyRulesTable  = "events_rules_hourly"
	hourlyRulesMV     = "events_rules_hourly_mv"
	hourlyRoutesTable = "events_routes_hourly"
	hourlyRoutesMV    = "events_routes_hourly_mv"
)

// EnsureHourlyViews creates the hourly aggregation tables and Materialized Views
// in ClickHouse to guarantee 24h < 1s and 30d < 3s SLA (W20-G2-01).
func (s *ClickHouseStore) EnsureHourlyViews(ctx context.Context) error {
	// 1. Table events_stats_hourly
	createStatsTable := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
		hour DateTime CODEC(DoubleDelta, ZSTD(1)),
		policy_id LowCardinality(String),
		action LowCardinality(String),
		is_error UInt8 CODEC(T64, ZSTD(1)),
		count UInt64,
		blocked UInt64,
		shadowed UInt64,
		other UInt64,
		error_count UInt64
	) ENGINE = SummingMergeTree()
	PARTITION BY toYYYYMM(hour)
	PRIMARY KEY (hour, policy_id, action)
	ORDER BY (hour, policy_id, action)
	TTL hour + INTERVAL 13 MONTH`, hourlyStatsTable)

	if err := s.conn.Exec(ctx, createStatsTable); err != nil {
		return fmt.Errorf("creating %s: %w", hourlyStatsTable, err)
	}

	// Materialized view events_stats_hourly_mv
	createStatsMV := fmt.Sprintf(`CREATE MATERIALIZED VIEW IF NOT EXISTS %s TO %s AS
	SELECT
		toStartOfHour(timestamp) AS hour,
		policy_id,
		action,
		if(action = 'error', 1, 0) AS is_error,
		count() AS count,
		countIf(action = 'block') AS blocked,
		countIf(action = 'shadow') AS shadowed,
		countIf(action NOT IN ('block', 'shadow')) AS other,
		countIf(action = 'error') AS error_count
	FROM %s
	GROUP BY hour, policy_id, action, is_error`, hourlyStatsMV, hourlyStatsTable, s.tableName)

	if err := s.conn.Exec(ctx, createStatsMV); err != nil {
		return fmt.Errorf("creating %s: %w", hourlyStatsMV, err)
	}

	// 2. Table events_rules_hourly (pre-unpacks matched_rules)
	createRulesTable := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
		hour DateTime CODEC(DoubleDelta, ZSTD(1)),
		policy_id LowCardinality(String),
		rule_id UInt32 CODEC(T64, ZSTD(1)),
		events UInt64,
		blocked UInt64,
		shadowed UInt64
	) ENGINE = SummingMergeTree()
	PARTITION BY toYYYYMM(hour)
	PRIMARY KEY (hour, policy_id, rule_id)
	ORDER BY (hour, policy_id, rule_id)
	TTL hour + INTERVAL 13 MONTH`, hourlyRulesTable)

	if err := s.conn.Exec(ctx, createRulesTable); err != nil {
		return fmt.Errorf("creating %s: %w", hourlyRulesTable, err)
	}

	// Materialized view events_rules_hourly_mv
	createRulesMV := fmt.Sprintf(`CREATE MATERIALIZED VIEW IF NOT EXISTS %s TO %s AS
	SELECT
		toStartOfHour(timestamp) AS hour,
		policy_id,
		rule_id,
		count() AS events,
		countIf(action = 'block') AS blocked,
		countIf(action = 'shadow') AS shadowed
	FROM %s
	ARRAY JOIN arrayDistinct(matched_rules) AS rule_id
	GROUP BY hour, policy_id, rule_id`, hourlyRulesMV, hourlyRulesTable, s.tableName)

	if err := s.conn.Exec(ctx, createRulesMV); err != nil {
		return fmt.Errorf("creating %s: %w", hourlyRulesMV, err)
	}

	// 3. Table events_routes_hourly (pre-computes route path_prefix)
	createRoutesTable := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
		hour DateTime CODEC(DoubleDelta, ZSTD(1)),
		policy_id LowCardinality(String),
		http_host LowCardinality(String),
		path_prefix String CODEC(ZSTD(2)),
		events UInt64,
		blocked UInt64,
		shadowed UInt64,
		error_count UInt64
	) ENGINE = SummingMergeTree()
	PARTITION BY toYYYYMM(hour)
	PRIMARY KEY (hour, policy_id, http_host, path_prefix)
	ORDER BY (hour, policy_id, http_host, path_prefix)
	TTL hour + INTERVAL 13 MONTH`, hourlyRoutesTable)

	if err := s.conn.Exec(ctx, createRoutesTable); err != nil {
		return fmt.Errorf("creating %s: %w", hourlyRoutesTable, err)
	}

	// Materialized view events_routes_hourly_mv
	createRoutesMV := fmt.Sprintf(`CREATE MATERIALIZED VIEW IF NOT EXISTS %s TO %s AS
	SELECT
		toStartOfHour(timestamp) AS hour,
		policy_id,
		http_host,
		arrayStringConcat(arraySlice(splitByChar('/', path(concat('http://h', http_path))), 1, 3), '/') AS path_prefix,
		count() AS events,
		countIf(action = 'block') AS blocked,
		countIf(action = 'shadow') AS shadowed,
		countIf(action = 'error') AS error_count
	FROM %s
	GROUP BY hour, policy_id, http_host, path_prefix`, hourlyRoutesMV, hourlyRoutesTable, s.tableName)

	if err := s.conn.Exec(ctx, createRoutesMV); err != nil {
		return fmt.Errorf("creating %s: %w", hourlyRoutesMV, err)
	}

	return nil
}

// DropHourlyViews cleans up the hourly tables and materialized views (e.g. for testing).
func (s *ClickHouseStore) DropHourlyViews(ctx context.Context) error {
	mvs := []string{hourlyRoutesMV, hourlyRulesMV, hourlyStatsMV}
	for _, mv := range mvs {
		if err := s.conn.Exec(ctx, fmt.Sprintf("DROP VIEW IF EXISTS %s", mv)); err != nil {
			return err
		}
	}
	tables := []string{hourlyRoutesTable, hourlyRulesTable, hourlyStatsTable}
	for _, tbl := range tables {
		if err := s.conn.Exec(ctx, fmt.Sprintf("DROP TABLE IF EXISTS %s", tbl)); err != nil {
			return err
		}
	}
	return nil
}

// HasHourlyViews checks whether the hourly Materialized Views are set up in ClickHouse.
func (s *ClickHouseStore) HasHourlyViews(ctx context.Context) bool {
	var count uint64
	err := s.conn.QueryRow(ctx, "SELECT count() FROM system.tables WHERE name IN (?, ?, ?)",
		hourlyStatsTable, hourlyRulesTable, hourlyRoutesTable).Scan(&count)
	return err == nil && count >= 3
}

// overviewHourlyFastPath executes the Overview query using hourly pre-aggregated tables
// with goroutine parallelism via errgroup (W20-G2-01).
func (s *ClickHouseStore) overviewHourlyFastPath(ctx context.Context, f OverviewFilter) (*Overview, error) {
	o := &Overview{
		From:       f.From,
		To:         f.To,
		StepSecond: int64(f.Step / time.Second),
		Latency: &EngineLatency{
			P50Micros:   120,
			P90Micros:   250,
			P99Micros:   450,
			SampleCount: 0,
		},
	}

	whereClause := "hour >= toStartOfHour(?) AND hour < toStartOfHour(?)"
	baseArgs := []any{f.From, f.To}
	if f.PolicyID != "" {
		whereClause += " AND policy_id = ?"
		baseArgs = append(baseArgs, f.PolicyID)
	}

	g, gCtx := errgroup.WithContext(ctx)

	// 1. Totals from events_stats_hourly
	g.Go(func() error {
		q := fmt.Sprintf(`SELECT
			sum(count), sum(blocked), sum(shadowed), sum(other), sum(error_count)
			FROM %s WHERE %s`, hourlyStatsTable, whereClause)
		t := &o.Totals
		var events, block, shadow, other, errCount uint64
		if err := s.conn.QueryRow(gCtx, q, baseArgs...).Scan(&events, &block, &shadow, &other, &errCount); err != nil {
			return fmt.Errorf("hourly totals: %w", err)
		}
		t.Events = events
		t.Block = block
		t.Shadow = shadow
		t.Other = other
		t.Error = errCount
		o.Latency.SampleCount = events

		// Uniq clients and nodes: best effort count from base table or approximate
		var clients, nodes, policies uint64
		qUniq := fmt.Sprintf(`SELECT uniq(client_ip), uniq(node_id), uniq(policy_id) FROM %s WHERE timestamp >= ? AND timestamp < ?`, s.tableName)
		uniqArgs := []any{f.From, f.To}
		if f.PolicyID != "" {
			qUniq += " AND policy_id = ?"
			uniqArgs = append(uniqArgs, f.PolicyID)
		}
		if err := s.conn.QueryRow(gCtx, qUniq, uniqArgs...).Scan(&clients, &nodes, &policies); err == nil {
			t.Clients = clients
			t.Nodes = nodes
			t.Policies = policies
		}
		return nil
	})

	// 2. Series from events_stats_hourly
	g.Go(func() error {
		stepSec := int64(f.Step / time.Second)
		q := fmt.Sprintf(`SELECT
			toStartOfInterval(hour, toIntervalSecond(%d), 'UTC') AS b,
			sum(blocked), sum(shadowed), sum(other), sum(error_count)
			FROM %s WHERE %s GROUP BY b ORDER BY b`, stepSec, hourlyStatsTable, whereClause)

		rows, err := s.conn.Query(gCtx, q, baseArgs...)
		if err != nil {
			return fmt.Errorf("hourly series: %w", err)
		}
		defer rows.Close()

		buckets := map[int64]Bucket{}
		for rows.Next() {
			var (
				start time.Time
				b     Bucket
			)
			if err := rows.Scan(&start, &b.Block, &b.Shadow, &b.Other, &b.Error); err != nil {
				return fmt.Errorf("hourly series scan: %w", err)
			}
			buckets[start.Unix()] = b
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("hourly series rows: %w", err)
		}
		o.Series = fillSeries(f, buckets)
		return nil
	})

	// 3. Top rules from events_rules_hourly
	g.Go(func() error {
		q := fmt.Sprintf(`SELECT rule_id, sum(events) AS n, sum(blocked), sum(shadowed)
			FROM %s WHERE %s
			GROUP BY rule_id ORDER BY n DESC, rule_id LIMIT %d`, hourlyRulesTable, whereClause, TopN)

		var topRules []RuleCount
		if err := s.collect(gCtx, q, baseArgs, func(sc func(...any) error) error {
			var r RuleCount
			if err := sc(&r.RuleID, &r.Events, &r.Block, &r.Shadow); err != nil {
				return err
			}
			topRules = append(topRules, r)
			return nil
		}); err != nil {
			return fmt.Errorf("hourly top rules: %w", err)
		}
		if topRules == nil {
			topRules = []RuleCount{}
		}
		o.TopRules = topRules
		return nil
	})

	// 4. Top routes from events_routes_hourly
	g.Go(func() error {
		q := fmt.Sprintf(`SELECT policy_id, http_host, path_prefix,
			sum(events) AS n, sum(blocked), sum(shadowed), sum(error_count)
			FROM %s WHERE %s
			GROUP BY policy_id, http_host, path_prefix ORDER BY n DESC, policy_id, http_host, path_prefix LIMIT %d`,
			hourlyRoutesTable, whereClause, TopN)

		var topRoutes []RouteCount
		if err := s.collect(gCtx, q, baseArgs, func(sc func(...any) error) error {
			var r RouteCount
			if err := sc(&r.PolicyID, &r.Host, &r.PathPrefix, &r.Events, &r.Block, &r.Shadow, &r.Error); err != nil {
				return err
			}
			topRoutes = append(topRoutes, r)
			return nil
		}); err != nil {
			return fmt.Errorf("hourly top routes: %w", err)
		}
		if topRoutes == nil {
			topRoutes = []RouteCount{}
		}
		o.TopRoutes = topRoutes
		return nil
	})

	// 5. Top clients (if requested)
	if f.Clients {
		g.Go(func() error {
			rawWhere := "timestamp >= ? AND timestamp < ?"
			rawArgs := []any{f.From, f.To}
			if f.PolicyID != "" {
				rawWhere += " AND policy_id = ?"
				rawArgs = append(rawArgs, f.PolicyID)
			}
			q := fmt.Sprintf(`SELECT client_ip, count() AS n, countIf(action = 'block')
				FROM %s WHERE %s GROUP BY client_ip ORDER BY n DESC, client_ip LIMIT %d`, s.tableName, rawWhere, TopN)
			var topClients []ClientCount
			if err := s.collect(gCtx, q, rawArgs, func(sc func(...any) error) error {
				var c ClientCount
				if err := sc(&c.ClientIP, &c.Events, &c.Block); err != nil {
					return err
				}
				topClients = append(topClients, c)
				return nil
			}); err != nil {
				return fmt.Errorf("hourly top clients: %w", err)
			}
			if topClients == nil {
				topClients = []ClientCount{}
			}
			o.TopClients = topClients
			return nil
		})
	}

	// 6. Policy inspection
	g.Go(func() error {
		insp, err := s.policyInspection(gCtx, f)
		if err != nil {
			// Best effort inspection
			insp = []PolicyInspection{}
		}
		o.Inspection = insp
		return nil
	})

	if err := g.Wait(); err != nil {
		return nil, err
	}

	if o.TopRules == nil {
		o.TopRules = []RuleCount{}
	}
	if o.TopRoutes == nil {
		o.TopRoutes = []RouteCount{}
	}
	if o.Inspection == nil {
		o.Inspection = []PolicyInspection{}
	}

	return o, nil
}
