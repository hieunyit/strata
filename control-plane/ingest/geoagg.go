package ingest

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
)

// GeoIP aggregates (W17-G2-01, nginx-module.md › Bản đồ GeoIP › Pipeline):
// materialized views of the events table, per minute by (policy, action,
// attack type, country, ASN) and per 5 minutes by geohash cell (precision 4)
// for the city layer.
//
// The events table can hold an event twice until it merges (a batch resent
// after a write timed out, or after a crash between the ClickHouse write and
// the watermark commit): the views keep uniqCombined64 states of block_id,
// not counts, so a resent event is counted once. uniqCombined64 is exact for
// small sets and within about 1% (HyperLogLog) for large ones: these are
// dashboard figures; exact counts come from the events table.
//
// "site" of the design is left out: events carry no site (connector group)
// yet.
const (
	GeoMinuteTable = "events_geo_minute_v1"
	GeoGridTable   = "events_geo_grid_v1"
	geoMinuteView  = "events_geo_minute_v1_mv"
	geoGridView    = "events_geo_grid_v1_mv"
	geoMarksTable  = "strata_aggregate_backfills"
)

// AttackTypeSQL classifies an event by the rules it matched (matched_rules),
// first family that matched in this order. The engine scores layers, not
// attack types, so score_sqli/score_xss stay 0 and cannot be used. Ranges:
// docs/design/strata-overview.md › Rule ID; 9xxxxx are CRS IDs by file.
const AttackTypeSQL = `multiIf(
	empty(matched_rules), 'none',
	arrayExists(r -> intDiv(r, 1000) = 942 OR r = 300002, matched_rules), 'sqli',
	arrayExists(r -> intDiv(r, 1000) = 941 OR r = 300010, matched_rules), 'xss',
	arrayExists(r -> intDiv(r, 1000) = 932, matched_rules), 'rce',
	arrayExists(r -> intDiv(r, 1000) = 930, matched_rules), 'lfi',
	arrayExists(r -> intDiv(r, 1000) = 931, matched_rules), 'rfi',
	arrayExists(r -> intDiv(r, 1000) IN (933, 934, 944) OR r BETWEEN 300001 AND 300099, matched_rules), 'injection_other',
	arrayExists(r -> intDiv(r, 1000) IN (913, 943), matched_rules), 'scanner',
	arrayExists(r -> r BETWEEN 700000 AND 799999, matched_rules), 'virtual_patch',
	arrayExists(r -> r BETWEEN 400000 AND 499999, matched_rules), 'signature',
	arrayExists(r -> r BETWEEN 500000 AND 599999, matched_rules), 'bot',
	arrayExists(r -> intDiv(r, 1000) IN (920, 921) OR r BETWEEN 100000 AND 199999, matched_rules), 'protocol',
	arrayExists(r -> r BETWEEN 800000 AND 899999, matched_rules), 'custom',
	'other')`

// AttackTypes are the values of AttackTypeSQL.
var AttackTypes = []string{"none", "sqli", "xss", "rce", "lfi", "rfi", "injection_other", "scanner",
	"virtual_patch", "signature", "bot", "protocol", "custom", "other"}

// Location columns as Get/Search present them: unversioned (legacy,
// unverified) metadata is withheld, INTERNAL kept (sanitizeStoredGeoIP).
const (
	geoCountrySQL = `multiIf(geoip_version != '', country_iso, country_iso = 'INTERNAL', 'INTERNAL', '')`
	geoASNSQL     = `if(geoip_version != '', asn, 0)`
	geoASOrgSQL   = `if(geoip_version != '', as_org, '')`
)

func (s *ClickHouseStore) geoMinuteSelect(where string) string {
	return fmt.Sprintf(`SELECT toStartOfMinute(timestamp) AS minute, policy_id, action,
		%s AS attack_type, %s AS country_iso, %s AS asn,
		any(%s) AS as_org, uniqCombined64State(block_id) AS events
	FROM %s %s
	GROUP BY minute, policy_id, action, attack_type, country_iso, asn`,
		AttackTypeSQL, geoCountrySQL, geoASNSQL, geoASOrgSQL, s.tableName, where)
}

func (s *ClickHouseStore) geoGridSelect(where string) string {
	cond := `geoip_version != '' AND lat IS NOT NULL AND lon IS NOT NULL
		AND country_iso NOT IN ('', 'INTERNAL')`
	if where != "" {
		cond += " AND " + strings.TrimPrefix(where, "WHERE ")
	}
	return fmt.Sprintf(`SELECT toStartOfFiveMinutes(timestamp) AS window_start,
		toFixedString(geohashEncode(assumeNotNull(lon), assumeNotNull(lat), 4), 4) AS geohash,
		policy_id, action, %s AS attack_type, country_iso,
		any(city) AS city, uniqCombined64State(block_id) AS events
	FROM %s WHERE %s
	GROUP BY window_start, geohash, policy_id, action, attack_type, country_iso`,
		AttackTypeSQL, s.tableName, cond)
}

// EnsureGeoAggregates creates the aggregate tables and their views, sets
// their retention to months (<= 0 leaves it), and fills them from the events
// already stored the first time (BackfillGeoAggregates). Run after
// EnsureColumns.
func (s *ClickHouseStore) EnsureGeoAggregates(ctx context.Context, months int) error {
	stmts := []string{
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
			minute      DateTime('UTC') CODEC(DoubleDelta, ZSTD(1)),
			policy_id   LowCardinality(String),
			action      LowCardinality(String),
			attack_type LowCardinality(String),
			country_iso LowCardinality(String),
			asn         UInt32,
			as_org      SimpleAggregateFunction(any, String),
			events      AggregateFunction(uniqCombined64, String)
		) ENGINE = AggregatingMergeTree
		PARTITION BY toYYYYMM(minute)
		ORDER BY (minute, policy_id, action, attack_type, country_iso, asn)`, GeoMinuteTable),
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
			window_start DateTime('UTC') CODEC(DoubleDelta, ZSTD(1)),
			geohash     FixedString(4),
			policy_id   LowCardinality(String),
			action      LowCardinality(String),
			attack_type LowCardinality(String),
			country_iso LowCardinality(String),
			city        SimpleAggregateFunction(any, String),
			events      AggregateFunction(uniqCombined64, String)
		) ENGINE = AggregatingMergeTree
		PARTITION BY toYYYYMM(window_start)
		ORDER BY (window_start, geohash, policy_id, action, attack_type, country_iso)`, GeoGridTable),
		fmt.Sprintf(`CREATE MATERIALIZED VIEW IF NOT EXISTS %s TO %s AS %s`,
			geoMinuteView, GeoMinuteTable, s.geoMinuteSelect("")),
		fmt.Sprintf(`CREATE MATERIALIZED VIEW IF NOT EXISTS %s TO %s AS %s`,
			geoGridView, GeoGridTable, s.geoGridSelect("")),
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (name String, done_at DateTime('UTC'))
			ENGINE = ReplacingMergeTree ORDER BY name`, geoMarksTable),
	}
	for _, q := range stmts {
		if err := s.conn.Exec(ctx, q); err != nil {
			return fmt.Errorf("creating GeoIP aggregates: %w", err)
		}
	}
	if months > 0 {
		for _, t := range []struct{ table, col string }{{GeoMinuteTable, "minute"}, {GeoGridTable, "window_start"}} {
			// changing a TTL rewrites the table's parts: only when it differs
			var create string
			if err := s.conn.QueryRow(ctx,
				"SELECT create_table_query FROM system.tables WHERE database = currentDatabase() AND name = ?",
				t.table).Scan(&create); err != nil {
				return fmt.Errorf("reading %s: %w", t.table, err)
			}
			if strings.Contains(create, fmt.Sprintf("TTL %s + toIntervalMonth(%d)", t.col, months)) {
				continue
			}
			q := fmt.Sprintf("ALTER TABLE %s MODIFY TTL %s + toIntervalMonth(%d)", t.table, t.col, months)
			if err := s.conn.Exec(ctx, q); err != nil {
				return fmt.Errorf("setting the retention of %s: %w", t.table, err)
			}
		}
	}
	return nil
}

// geoBackfillMark names the backfill of these views in geoMarksTable.
const geoBackfillMark = "geo_v1"

// GeoBackfillDone reports whether the views were filled from the events
// stored before them.
func (s *ClickHouseStore) GeoBackfillDone(ctx context.Context) (bool, error) {
	var n uint64
	err := s.conn.QueryRow(ctx, fmt.Sprintf("SELECT count() FROM %s FINAL WHERE name = ?", geoMarksTable),
		geoBackfillMark).Scan(&n)
	return n > 0, err
}

// BackfillGeoAggregates adds the events stored before the views existed,
// one day at a time from from (inclusive). The states are of distinct
// block_id: events the views already have are not counted twice, so an
// interrupted backfill is simply run again. Marked done at the end.
func (s *ClickHouseStore) BackfillGeoAggregates(ctx context.Context, from time.Time) error {
	ctx = clickhouse.Context(ctx, clickhouse.WithSettings(clickhouse.Settings{"max_execution_time": 600}))
	day := from.UTC().Truncate(24 * time.Hour)
	end := time.Now().UTC().Add(time.Minute)
	for ; day.Before(end); day = day.Add(24 * time.Hour) {
		where := "WHERE timestamp >= ? AND timestamp < ?"
		next := day.Add(24 * time.Hour)
		if err := s.conn.Exec(ctx, fmt.Sprintf("INSERT INTO %s %s", GeoMinuteTable, s.geoMinuteSelect(where)), day, next); err != nil {
			return fmt.Errorf("GeoIP backfill (minute) %s: %w", day.Format("2006-01-02"), err)
		}
		if err := s.conn.Exec(ctx, fmt.Sprintf("INSERT INTO %s %s", GeoGridTable, s.geoGridSelect(where)), day, next); err != nil {
			return fmt.Errorf("GeoIP backfill (grid) %s: %w", day.Format("2006-01-02"), err)
		}
	}
	return s.conn.Exec(ctx, fmt.Sprintf("INSERT INTO %s VALUES (?, now())", geoMarksTable), geoBackfillMark)
}

// GeoFilter selects aggregated events: From is rounded down to the
// aggregates' step (minute, or 5 minutes for the grid).
type GeoFilter struct {
	From, To   time.Time
	PolicyID   string
	Action     string
	AttackType string
	CountryISO string
	ASN        uint32
	Limit      int
}

// where selects the buckets of [From, To): From is rounded down to the
// bucket (step) holding it, so its events are not left out.
func (f GeoFilter) where(timeCol string, step time.Duration) (string, []any) {
	conds := []string{timeCol + " >= ? AND " + timeCol + " < ?"}
	args := []any{f.From.UTC().Truncate(step), f.To.UTC()}
	for _, c := range []struct {
		col string
		v   any
		set bool
	}{
		{"policy_id", f.PolicyID, f.PolicyID != ""},
		{"action", f.Action, f.Action != ""},
		{"attack_type", f.AttackType, f.AttackType != ""},
		{"country_iso", f.CountryISO, f.CountryISO != ""},
		{"asn", f.ASN, f.ASN != 0},
	} {
		if c.set {
			conds = append(conds, c.col+" = ?")
			args = append(args, c.v)
		}
	}
	return strings.Join(conds, " AND "), args
}

func (f GeoFilter) limit() int {
	switch {
	case f.Limit <= 0:
		return 50
	case f.Limit > 1000:
		return 1000
	}
	return f.Limit
}

// GeoCount is one row of an aggregate: distinct events, blocked among them,
// and the attack type with the most events.
type GeoCount struct {
	Key       string   `json:"key"`
	Label     string   `json:"label,omitempty"`
	Events    uint64   `json:"events"`
	Blocked   uint64   `json:"blocked"`
	TopAttack string   `json:"top_attack_type"`
	Lat       *float64 `json:"lat,omitempty"`
	Lon       *float64 `json:"lon,omitempty"`
}

// GeoByCountry ranks countries (empty and INTERNAL included: the caller
// decides how to show them), most events first.
func (s *ClickHouseStore) GeoByCountry(ctx context.Context, f GeoFilter) ([]GeoCount, error) {
	return s.geoRank(ctx, f, GeoMinuteTable, "minute", time.Minute, "country_iso", "''")
}

// GeoByASN ranks autonomous systems (ASN 0: unknown), most events first.
func (s *ClickHouseStore) GeoByASN(ctx context.Context, f GeoFilter) ([]GeoCount, error) {
	return s.geoRank(ctx, f, GeoMinuteTable, "minute", time.Minute, "toString(asn)", "any(as_org)")
}

// GeoByCell gives the geohash cells (precision 4, about 20-40 km) with
// events, at each cell's center (never an IP's coordinates).
func (s *ClickHouseStore) GeoByCell(ctx context.Context, f GeoFilter) ([]GeoCount, error) {
	f.ASN = 0 // not a dimension of the grid
	out, err := s.geoRank(ctx, f, GeoGridTable, "window_start", 5*time.Minute, "geohash", "any(city)")
	if err != nil {
		return nil, err
	}
	for i := range out {
		lon, lat, ok := geohashCenter(out[i].Key)
		if ok {
			out[i].Lat, out[i].Lon = &lat, &lon
		}
	}
	return out, nil
}

func (s *ClickHouseStore) geoRank(ctx context.Context, f GeoFilter, table, timeCol string, step time.Duration, key, label string) ([]GeoCount, error) {
	where, args := f.where(timeCol, step)
	// per attack type first: rows of one type are distinct events, so the
	// per-type counts add up, and the type with most events is kept
	q := fmt.Sprintf(`SELECT k, any(l), sum(n), sum(b), argMax(attack_type, n)
		FROM (
			SELECT %s AS k, %s AS l, attack_type,
				uniqCombined64Merge(events) AS n,
				uniqCombined64MergeIf(events, action = 'block') AS b
			FROM %s WHERE %s
			GROUP BY k, attack_type
		)
		GROUP BY k ORDER BY sum(n) DESC, k LIMIT %d`, key, label, table, where, f.limit())
	rows, err := s.conn.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("GeoIP aggregates: %w", err)
	}
	defer rows.Close()
	var out []GeoCount
	for rows.Next() {
		var c GeoCount
		if err := rows.Scan(&c.Key, &c.Label, &c.Events, &c.Blocked, &c.TopAttack); err != nil {
			return nil, fmt.Errorf("GeoIP aggregates: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

const geohashAlphabet = "0123456789bcdefghjkmnpqrstuvwxyz"

// geohashCenter decodes a geohash to the center of its cell.
func geohashCenter(h string) (lon, lat float64, ok bool) {
	lonMin, lonMax, latMin, latMax := -180.0, 180.0, -90.0, 90.0
	even := true
	for i := 0; i < len(h); i++ {
		v := strings.IndexByte(geohashAlphabet, h[i])
		if v < 0 {
			return 0, 0, false
		}
		for bit := 4; bit >= 0; bit-- {
			on := v>>bit&1 == 1
			if even {
				mid := (lonMin + lonMax) / 2
				if on {
					lonMin = mid
				} else {
					lonMax = mid
				}
			} else {
				mid := (latMin + latMax) / 2
				if on {
					latMin = mid
				} else {
					latMax = mid
				}
			}
			even = !even
		}
	}
	return (lonMin + lonMax) / 2, (latMin + latMax) / 2, len(h) > 0
}
