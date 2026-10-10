// Package db holds the control plane's PostgreSQL schema. Migrations are
// embedded SQL files NNNN_name.up.sql / NNNN_name.down.sql, each applied in
// its own transaction; the applied versions are kept in schema_migrations.
package db

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var files embed.FS

// lockID serializes migrations of control planes sharing a database.
const lockID = 0x5354524154410001 // "STRATA" + 1

type migration struct {
	version  int
	name     string
	up, down string
}

func load() ([]migration, error) {
	entries, err := fs.ReadDir(files, "migrations")
	if err != nil {
		return nil, err
	}
	byVersion := map[int]*migration{}
	for _, e := range entries {
		n := e.Name()
		dir := ""
		switch {
		case strings.HasSuffix(n, ".up.sql"):
			dir = "up"
		case strings.HasSuffix(n, ".down.sql"):
			dir = "down"
		default:
			return nil, fmt.Errorf("db: unexpected file migrations/%s", n)
		}
		num, rest, ok := strings.Cut(n, "_")
		v, err := strconv.Atoi(num)
		if !ok || err != nil || v <= 0 {
			return nil, fmt.Errorf("db: bad migration name %s", n)
		}
		body, err := files.ReadFile("migrations/" + n)
		if err != nil {
			return nil, err
		}
		m := byVersion[v]
		if m == nil {
			m = &migration{version: v, name: strings.TrimSuffix(strings.TrimSuffix(rest, ".up.sql"), ".down.sql")}
			byVersion[v] = m
		}
		if dir == "up" {
			m.up = string(body)
		} else {
			m.down = string(body)
		}
	}
	out := make([]migration, 0, len(byVersion))
	for _, m := range byVersion {
		if m.up == "" || m.down == "" {
			return nil, fmt.Errorf("db: migration %04d needs both an up and a down file", m.version)
		}
		out = append(out, *m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	for i, m := range out {
		if m.version != i+1 {
			return nil, fmt.Errorf("db: migrations are not numbered 1..n (found %04d at position %d)", m.version, i+1)
		}
	}
	return out, nil
}

// Latest is the newest schema version this build knows.
func Latest() (int, error) {
	ms, err := load()
	if err != nil {
		return 0, err
	}
	return len(ms), nil
}

// Migrate brings the schema to version target (0 drops everything this
// package created); it applies up or down migrations as needed.
func Migrate(ctx context.Context, pool *pgxpool.Pool, target int) error {
	ms, err := load()
	if err != nil {
		return err
	}
	if target < 0 || target > len(ms) {
		return fmt.Errorf("db: target version %d, this build knows 0..%d", target, len(ms))
	}
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("db: %w", err)
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", int64(lockID)); err != nil {
		return fmt.Errorf("db: lock: %w", err)
	}
	defer func() { _, _ = conn.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", int64(lockID)) }()

	if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version integer PRIMARY KEY, name text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return fmt.Errorf("db: schema_migrations: %w", err)
	}
	cur, err := current(ctx, conn.Conn())
	if err != nil {
		return err
	}
	if cur > len(ms) {
		return fmt.Errorf("db: schema is at version %d, newer than this build (%d)", cur, len(ms))
	}
	for v := cur + 1; v <= target; v++ {
		m := ms[v-1]
		if err := step(ctx, conn.Conn(), m.up, "INSERT INTO schema_migrations (version, name) VALUES ($1, $2)", m.version, m.name); err != nil {
			return fmt.Errorf("db: up %04d_%s: %w", m.version, m.name, err)
		}
	}
	for v := cur; v > target; v-- {
		m := ms[v-1]
		if err := step(ctx, conn.Conn(), m.down, "DELETE FROM schema_migrations WHERE version = $1 AND name = $2", m.version, m.name); err != nil {
			return fmt.Errorf("db: down %04d_%s: %w", m.version, m.name, err)
		}
	}
	return nil
}

// Version returns the applied schema version, 0 for an empty database.
func Version(ctx context.Context, pool *pgxpool.Pool) (int, error) {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return 0, fmt.Errorf("db: %w", err)
	}
	defer conn.Release()
	var exists bool
	if err := conn.QueryRow(ctx, "SELECT to_regclass('schema_migrations') IS NOT NULL").Scan(&exists); err != nil {
		return 0, fmt.Errorf("db: %w", err)
	}
	if !exists {
		return 0, nil
	}
	return current(ctx, conn.Conn())
}

func current(ctx context.Context, conn *pgx.Conn) (int, error) {
	var v int
	if err := conn.QueryRow(ctx, "SELECT coalesce(max(version), 0) FROM schema_migrations").Scan(&v); err != nil {
		return 0, fmt.Errorf("db: current version: %w", err)
	}
	return v, nil
}

func step(ctx context.Context, conn *pgx.Conn, sql, record string, version int, name string) error {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, sql); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, record, version, name); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
