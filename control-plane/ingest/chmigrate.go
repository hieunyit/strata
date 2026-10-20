package ingest

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"strings"
)

// schemaSQL is the first schema of the events database. ClickHouse also
// runs it when the lab creates its volume; the control plane applies it as
// migration 1 (CP-A08), so an empty database needs nothing else.
//
//go:embed schema.sql
var schemaSQL string

// migrationsTable records the applied migrations of the events database.
const migrationsTable = "strata_schema_migrations"

// chMigration is one step of the events schema. Every step is idempotent
// (IF NOT EXISTS, or checks first): a database made before this list
// existed, by schema.sql and the Ensure functions, takes them all again
// without change.
type chMigration struct {
	version uint32
	name    string
	up      func(*ClickHouseStore, context.Context) error
}

// chMigrations, in order. Append only; never edit a released step.
var chMigrations = []chMigration{
	{1, "events, node_seq and policy_requests tables (schema.sql)", (*ClickHouseStore).applySchemaSQL},
	{2, "event context, GeoIP and JA4 columns; GeoIP coordinates as Nullable(Float64)", (*ClickHouseStore).EnsureColumns},
	{3, "policy_requests table (databases made before RV-N-01)", func(s *ClickHouseStore, ctx context.Context) error {
		return s.EnsurePolicyRequests(ctx, 0)
	}},
	{4, "GeoIP aggregate tables and their views", func(s *ClickHouseStore, ctx context.Context) error {
		return s.EnsureGeoAggregates(ctx, 0)
	}},
	{5, "hourly statistics rollup (W20-G2-01) and the received_at index of events", (*ClickHouseStore).EnsureStatsRollup},
	{6, "engine_time table (W20-F-01)", (*ClickHouseStore).EnsureEngineTime},
}

// LatestCHMigration is the schema version this build brings.
func LatestCHMigration() uint32 { return chMigrations[len(chMigrations)-1].version }

// ErrCHSchemaNewer: the database was migrated by a newer build.
var ErrCHSchemaNewer = errors.New("ClickHouse schema is newer than this build")

// applySchemaSQL runs schema.sql statement by statement.
func (s *ClickHouseStore) applySchemaSQL(ctx context.Context) error {
	for _, stmt := range splitSQL(schemaSQL) {
		if err := s.conn.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("schema.sql: %w", err)
		}
	}
	return nil
}

// splitSQL splits on the semicolons that end a line, without the comment
// lines (schema.sql has no semicolon inside a statement's text).
func splitSQL(sql string) []string {
	var out []string
	var cur strings.Builder
	for _, line := range strings.Split(sql, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "--") {
			continue
		}
		cur.WriteString(line)
		cur.WriteString("\n")
		if strings.HasSuffix(t, ";") {
			if stmt := strings.TrimSuffix(strings.TrimSpace(cur.String()), ";"); stmt != "" {
				out = append(out, stmt)
			}
			cur.Reset()
		}
	}
	if stmt := strings.TrimSpace(cur.String()); stmt != "" {
		out = append(out, stmt)
	}
	return out
}

// CHSchemaVersion is the highest migration applied, 0 for none.
func (s *ClickHouseStore) CHSchemaVersion(ctx context.Context) (uint32, error) {
	if err := s.conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS `+migrationsTable+` (
		version UInt32, name String, applied_at DateTime('UTC') DEFAULT now())
		ENGINE = ReplacingMergeTree ORDER BY version`); err != nil {
		return 0, fmt.Errorf("creating %s: %w", migrationsTable, err)
	}
	var v uint32
	if err := s.conn.QueryRow(ctx, "SELECT toUInt32(max(version)) FROM "+migrationsTable).Scan(&v); err != nil {
		return 0, fmt.Errorf("reading %s: %w", migrationsTable, err)
	}
	return v, nil
}

// Migrate applies the migrations the database lacks, in order, recording
// each; a database of a newer build is ErrCHSchemaNewer and left alone.
// Returns the versions applied.
func (s *ClickHouseStore) Migrate(ctx context.Context) ([]uint32, error) {
	current, err := s.CHSchemaVersion(ctx)
	if err != nil {
		return nil, err
	}
	if current > LatestCHMigration() {
		return nil, fmt.Errorf("%w: at version %d, this build knows %d", ErrCHSchemaNewer, current, LatestCHMigration())
	}
	var applied []uint32
	for _, m := range chMigrations {
		if m.version <= current {
			continue
		}
		if err := m.up(s, ctx); err != nil {
			return applied, fmt.Errorf("ClickHouse migration %d (%s): %w", m.version, m.name, err)
		}
		if err := s.conn.Exec(ctx, "INSERT INTO "+migrationsTable+" (version, name) VALUES (?, ?)", m.version, m.name); err != nil {
			return applied, fmt.Errorf("recording ClickHouse migration %d: %w", m.version, err)
		}
		applied = append(applied, m.version)
	}
	s.migrated.Store(true)
	return applied, nil
}

// Configure applies the retention settings (not schema: they follow the
// configuration and may change at every start).
func (s *ClickHouseStore) Configure(ctx context.Context, ttlDays, geoMonths int) error {
	if err := s.EnsureTTL(ctx, ttlDays); err != nil {
		return err
	}
	if err := s.EnsurePolicyRequests(ctx, ttlDays); err != nil {
		return err
	}
	if err := s.EnsureGeoAggregates(ctx, geoMonths); err != nil {
		return err
	}
	return s.EnsureStatsTTL(ctx, geoMonths)
}

// Migrated reports whether Migrate succeeded in this process: until then
// the events part of the control plane is degraded.
func (s *ClickHouseStore) Migrated() bool { return s.migrated.Load() }
