package ingest

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	geoMinuteTable = "events_geo_minute"
	geoMinuteMV    = "events_geo_minute_mv"
	geoGridTable   = "events_geo_grid"
	geoGridMV      = "events_geo_grid_mv"
)

// GeoCountryStat represents attack and traffic statistics aggregated by country.
type GeoCountryStat struct {
	CountryISO    string `json:"country_iso"`
	Events        uint64 `json:"events"`
	Blocked       uint64 `json:"blocked"`
	TopAttackType string `json:"top_attack_type"`
}

// GeoASNStat represents traffic and block numbers aggregated by autonomous system.
type GeoASNStat struct {
	ASN     uint32 `json:"asn"`
	ASOrg   string `json:"as_org"`
	Events  uint64 `json:"events"`
	Blocked uint64 `json:"blocked"`
}

// GeoGridStat represents cluster points aggregated on a 5-minute geohash4 grid.
type GeoGridStat struct {
	Geohash       string  `json:"geohash"`
	Lat           float32 `json:"lat"`
	Lon           float32 `json:"lon"`
	City          string  `json:"city"`
	CountryISO    string  `json:"country_iso"`
	Events        uint64  `json:"events"`
	Blocked       uint64  `json:"blocked"`
	TopAttackType string  `json:"top_attack_type"`
}

// GeoStatsFilter defines querying parameters for GeoIP analytics.
type GeoStatsFilter struct {
	From     time.Time
	To       time.Time
	GroupBy  string // "country", "city", "asn", "all"
	PolicyID string
	Action   string
	Limit    int
}

// GeoStatsResponse wraps all aggregated geo-spatial data points.
type GeoStatsResponse struct {
	From      time.Time        `json:"from"`
	To        time.Time        `json:"to"`
	Countries []GeoCountryStat `json:"countries,omitempty"`
	ASNs      []GeoASNStat     `json:"asns,omitempty"`
	Grid      []GeoGridStat    `json:"grid,omitempty"`
}

// GeoStatsStore defines the capability to retrieve aggregated GeoIP statistics.
type GeoStatsStore interface {
	GeoStats(ctx context.Context, f GeoStatsFilter) (*GeoStatsResponse, error)
}

// EnsureGeoViews creates the Materialized Views and target SummingMergeTree tables in ClickHouse.
func (s *ClickHouseStore) EnsureGeoViews(ctx context.Context) error {
	// 1. Table events_geo_minute
	createMinuteTable := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
		minute DateTime CODEC(DoubleDelta, ZSTD(1)),
		site LowCardinality(String),
		policy_id LowCardinality(String),
		action LowCardinality(String),
		attack_type LowCardinality(String),
		country_iso LowCardinality(String),
		asn UInt32 CODEC(T64, ZSTD(1)),
		as_org LowCardinality(String),
		count UInt64,
		blocked_count UInt64
	) ENGINE = SummingMergeTree()
	PARTITION BY toYYYYMM(minute)
	PRIMARY KEY (minute, policy_id, action, attack_type, country_iso, asn, as_org)
	ORDER BY (minute, policy_id, action, attack_type, country_iso, asn, as_org)
	TTL minute + INTERVAL 13 MONTH`, geoMinuteTable)

	if err := s.conn.Exec(ctx, createMinuteTable); err != nil {
		return fmt.Errorf("creating %s: %w", geoMinuteTable, err)
	}

	// Materialized view events_geo_minute_mv
	createMinuteMV := fmt.Sprintf(`CREATE MATERIALIZED VIEW IF NOT EXISTS %s TO %s AS
	SELECT
		toStartOfMinute(timestamp) AS minute,
		connector_type AS site,
		policy_id,
		action,
		if(score_sqli > 0, 'sqli', if(score_xss > 0, 'xss', if(score_protocol > 0, 'protocol', 'anomaly'))) AS attack_type,
		country_iso,
		asn,
		as_org,
		count() AS count,
		countIf(action = 'block') AS blocked_count
	FROM %s
	GROUP BY minute, site, policy_id, action, attack_type, country_iso, asn, as_org`, geoMinuteMV, geoMinuteTable, s.tableName)

	if err := s.conn.Exec(ctx, createMinuteMV); err != nil {
		return fmt.Errorf("creating %s: %w", geoMinuteMV, err)
	}

	// 2. Table events_geo_grid
	createGridTable := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
		window_5m DateTime CODEC(DoubleDelta, ZSTD(1)),
		geohash4 LowCardinality(String),
		country_iso LowCardinality(String),
		city LowCardinality(String),
		lat Float32,
		lon Float32,
		attack_type LowCardinality(String),
		count UInt64,
		blocked_count UInt64
	) ENGINE = SummingMergeTree()
	PARTITION BY toYYYYMM(window_5m)
	PRIMARY KEY (window_5m, geohash4, attack_type)
	ORDER BY (window_5m, geohash4, attack_type)
	TTL window_5m + INTERVAL 13 MONTH`, geoGridTable)

	if err := s.conn.Exec(ctx, createGridTable); err != nil {
		return fmt.Errorf("creating %s: %w", geoGridTable, err)
	}

	// Materialized view events_geo_grid_mv
	createGridMV := fmt.Sprintf(`CREATE MATERIALIZED VIEW IF NOT EXISTS %s TO %s AS
	SELECT
		toStartOfFiveMinutes(timestamp) AS window_5m,
		geohashEncode(lon, lat, 4) AS geohash4,
		country_iso,
		any(city) AS city,
		round(avg(lat), 3) AS lat,
		round(avg(lon), 3) AS lon,
		if(score_sqli > 0, 'sqli', if(score_xss > 0, 'xss', if(score_protocol > 0, 'protocol', 'anomaly'))) AS attack_type,
		count() AS count,
		countIf(action = 'block') AS blocked_count
	FROM %s
	WHERE country_iso != 'INTERNAL' AND country_iso != '' AND lat != 0 AND lon != 0
	GROUP BY window_5m, geohash4, country_iso, attack_type`, geoGridMV, geoGridTable, s.tableName)

	if err := s.conn.Exec(ctx, createGridMV); err != nil {
		return fmt.Errorf("creating %s: %w", geoGridMV, err)
	}

	return nil
}

// GeoStats queries pre-aggregated tables in ClickHouse with sub-second performance.
func (s *ClickHouseStore) GeoStats(ctx context.Context, f GeoStatsFilter) (*GeoStatsResponse, error) {
	if f.From.IsZero() {
		f.From = time.Now().UTC().Add(-24 * time.Hour)
	}
	if f.To.IsZero() {
		f.To = time.Now().UTC()
	}
	limit := f.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 250 {
		limit = 250
	}

	resp := &GeoStatsResponse{
		From: f.From,
		To:   f.To,
	}

	where := []string{"minute >= ? AND minute <= ?"}
	args := []any{f.From, f.To}
	if f.PolicyID != "" {
		where = append(where, "policy_id = ?")
		args = append(args, f.PolicyID)
	}
	if f.Action != "" {
		where = append(where, "action = ?")
		args = append(args, f.Action)
	}
	whereSQL := strings.Join(where, " AND ")

	doCountry := f.GroupBy == "" || f.GroupBy == "country" || f.GroupBy == "all"
	doASN := f.GroupBy == "asn" || f.GroupBy == "all"
	doGrid := f.GroupBy == "city" || f.GroupBy == "grid" || f.GroupBy == "all"

	if doCountry {
		q := fmt.Sprintf(`SELECT country_iso, sum(count) as evts, sum(blocked_count) as blk, any(attack_type)
			FROM %s
			WHERE %s AND country_iso != '' AND country_iso != 'INTERNAL'
			GROUP BY country_iso
			ORDER BY evts DESC
			LIMIT ?`, geoMinuteTable, whereSQL)

		cArgs := append(args, limit)
		rows, err := s.conn.Query(ctx, q, cArgs...)
		if err != nil {
			return nil, fmt.Errorf("querying country stats from %s: %w", geoMinuteTable, err)
		}
		for rows.Next() {
			var st GeoCountryStat
			if err := rows.Scan(&st.CountryISO, &st.Events, &st.Blocked, &st.TopAttackType); err != nil {
				rows.Close()
				return nil, fmt.Errorf("scanning country stat: %w", err)
			}
			resp.Countries = append(resp.Countries, st)
		}
		rows.Close()
	}

	if doASN {
		q := fmt.Sprintf(`SELECT asn, any(as_org) as as_org, sum(count) as evts, sum(blocked_count) as blk
			FROM %s
			WHERE %s AND asn > 0
			GROUP BY asn
			ORDER BY evts DESC
			LIMIT ?`, geoMinuteTable, whereSQL)

		aArgs := append(args, limit)
		rows, err := s.conn.Query(ctx, q, aArgs...)
		if err != nil {
			return nil, fmt.Errorf("querying asn stats from %s: %w", geoMinuteTable, err)
		}
		for rows.Next() {
			var st GeoASNStat
			if err := rows.Scan(&st.ASN, &st.ASOrg, &st.Events, &st.Blocked); err != nil {
				rows.Close()
				return nil, fmt.Errorf("scanning asn stat: %w", err)
			}
			resp.ASNs = append(resp.ASNs, st)
		}
		rows.Close()
	}

	if doGrid {
		gridWhere := "window_5m >= ? AND window_5m <= ?"
		q := fmt.Sprintf(`SELECT geohash4, any(country_iso), any(city), any(lat), any(lon), any(attack_type), sum(count) as evts, sum(blocked_count) as blk
			FROM %s
			WHERE %s
			GROUP BY geohash4
			ORDER BY evts DESC
			LIMIT ?`, geoGridTable, gridWhere)

		rows, err := s.conn.Query(ctx, q, f.From, f.To, limit)
		if err != nil {
			return nil, fmt.Errorf("querying grid stats from %s: %w", geoGridTable, err)
		}
		for rows.Next() {
			var st GeoGridStat
			if err := rows.Scan(&st.Geohash, &st.CountryISO, &st.City, &st.Lat, &st.Lon, &st.TopAttackType, &st.Events, &st.Blocked); err != nil {
				rows.Close()
				return nil, fmt.Errorf("scanning grid stat: %w", err)
			}
			resp.Grid = append(resp.Grid, st)
		}
		rows.Close()
	}

	return resp, nil
}

// GeoStats on MockEventStore aggregates in-memory events for tests and offline harnesses.
func (m *MockEventStore) GeoStats(_ context.Context, f GeoStatsFilter) (*GeoStatsResponse, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if f.From.IsZero() {
		f.From = time.Now().UTC().Add(-24 * time.Hour)
	}
	if f.To.IsZero() {
		f.To = time.Now().UTC()
	}

	resp := &GeoStatsResponse{
		From: f.From,
		To:   f.To,
	}

	countryMap := make(map[string]*GeoCountryStat)
	asnMap := make(map[uint32]*GeoASNStat)
	gridMap := make(map[string]*GeoGridStat)

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
		if f.Action != "" && e.Action != f.Action {
			continue
		}

		isBlock := e.Action == "block"
		atkType := "anomaly"
		if e.ScoreSQLi > 0 {
			atkType = "sqli"
		} else if e.ScoreXSS > 0 {
			atkType = "xss"
		} else if e.ScoreProtocol > 0 {
			atkType = "protocol"
		}

		if e.CountryISO != "" && e.CountryISO != "INTERNAL" {
			cs, ok := countryMap[e.CountryISO]
			if !ok {
				cs = &GeoCountryStat{CountryISO: e.CountryISO, TopAttackType: atkType}
				countryMap[e.CountryISO] = cs
			}
			cs.Events++
			if isBlock {
				cs.Blocked++
			}
		}

		if e.ASN > 0 {
			as, ok := asnMap[e.ASN]
			if !ok {
				as = &GeoASNStat{ASN: e.ASN, ASOrg: e.ASOrg}
				asnMap[e.ASN] = as
			}
			as.Events++
			if isBlock {
				as.Blocked++
			}
		}

		if e.CountryISO != "" && e.CountryISO != "INTERNAL" && (e.Lat != 0 || e.Lon != 0) {
			key := fmt.Sprintf("%.2f,%.2f", e.Lat, e.Lon)
			gs, ok := gridMap[key]
			if !ok {
				gs = &GeoGridStat{
					Geohash:       key,
					Lat:           e.Lat,
					Lon:           e.Lon,
					City:          e.City,
					CountryISO:    e.CountryISO,
					TopAttackType: atkType,
				}
				gridMap[key] = gs
			}
			gs.Events++
			if isBlock {
				gs.Blocked++
			}
		}
	}

	for _, cs := range countryMap {
		resp.Countries = append(resp.Countries, *cs)
	}
	sort.Slice(resp.Countries, func(i, j int) bool {
		return resp.Countries[i].Events > resp.Countries[j].Events
	})

	for _, as := range asnMap {
		resp.ASNs = append(resp.ASNs, *as)
	}
	sort.Slice(resp.ASNs, func(i, j int) bool {
		return resp.ASNs[i].Events > resp.ASNs[j].Events
	})

	for _, gs := range gridMap {
		resp.Grid = append(resp.Grid, *gs)
	}
	sort.Slice(resp.Grid, func(i, j int) bool {
		return resp.Grid[i].Events > resp.Grid[j].Events
	})

	limit := f.Limit
	if limit <= 0 {
		limit = 50
	}
	if len(resp.Countries) > limit {
		resp.Countries = resp.Countries[:limit]
	}
	if len(resp.ASNs) > limit {
		resp.ASNs = resp.ASNs[:limit]
	}
	if len(resp.Grid) > limit {
		resp.Grid = resp.Grid[:limit]
	}

	return resp, nil
}
