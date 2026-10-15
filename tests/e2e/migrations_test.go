package e2e

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/strata/strata/control-plane/db"
)

// startPostgres runs an empty PostgreSQL 17 on a free local port.
func startPostgres(t *testing.T) *pgxpool.Pool {
	t.Helper()
	name := fmt.Sprintf("strata-e2e-pg-%d", time.Now().UnixNano()%1000000)
	out, err := exec.Command("docker", "run", "-d", "--rm", "--name", name,
		"-e", "POSTGRES_PASSWORD=strata", "-e", "POSTGRES_DB=strata",
		"-p", "127.0.0.1::5432", "postgres:17.11").CombinedOutput()
	if err != nil {
		t.Fatalf("start postgres: %v: %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "stop", "-t", "2", name).Run() })
	port, err := exec.Command("docker", "port", name, "5432/tcp").Output()
	if err != nil {
		t.Fatalf("docker port: %v", err)
	}
	hostPort := strings.TrimSpace(strings.Split(string(port), "\n")[0])
	dsn := "postgres://postgres:strata@" + hostPort + "/strata?sslmode=disable"

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	deadline := time.Now().Add(60 * time.Second)
	for {
		var one int
		if err := pool.QueryRow(ctx, "SELECT 1").Scan(&one); err == nil {
			return pool
		} else if time.Now().After(deadline) {
			t.Fatalf("postgres not ready: %v", err)
		}
		time.Sleep(300 * time.Millisecond)
	}
}

func userTables(t *testing.T, pool *pgxpool.Pool) []string {
	t.Helper()
	rows, err := pool.Query(context.Background(),
		`SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename <> 'schema_migrations' ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		out = append(out, n)
	}
	return out
}

// W03-G2-01: migrations go up and down cleanly on an empty database, and
// up again; running them twice changes nothing.
func TestMigrationsUpDownOnEmptyDatabase(t *testing.T) {
	pool := startPostgres(t)
	ctx := context.Background()
	latest, err := db.Latest()
	if err != nil {
		t.Fatal(err)
	}

	if v, err := db.Version(ctx, pool); err != nil || v != 0 {
		t.Fatalf("empty database: version %d, %v", v, err)
	}
	if err := db.Migrate(ctx, pool, latest); err != nil {
		t.Fatalf("up: %v", err)
	}
	want := []string{"audit_log", "bundles", "canary_trips", "connector_groups", "disabled_rules", "enrollment_tokens",
		"local_sessions", "local_users", "node_commands", "nodes", "operations", "policies", "policy_versions",
		"replay_sampling", "role_bindings", "rollout_nodes", "rollouts", "secrets", "service_accounts"}
	if got := userTables(t, pool); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("tables after up: %v", got)
	}
	if err := db.Migrate(ctx, pool, latest); err != nil {
		t.Fatalf("up twice: %v", err)
	}
	if v, _ := db.Version(ctx, pool); v != latest {
		t.Fatalf("version %d, want %d", v, latest)
	}

	// The four-eyes rule is in the schema.
	if _, err := pool.Exec(ctx, `INSERT INTO policies (id, name, etag, created_by) VALUES ('p1', 'example-api', 'e1', 'alice')`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO policy_versions (policy_id, version, spec, created_by, approved_by) VALUES ('p1', 1, '{}', 'alice', 'alice')`); err == nil {
		t.Fatal("a version approved by its author was stored")
	}

	if err := db.Migrate(ctx, pool, 0); err != nil {
		t.Fatalf("down: %v", err)
	}
	if got := userTables(t, pool); len(got) != 0 {
		t.Fatalf("tables after down: %v", got)
	}
	if v, _ := db.Version(ctx, pool); v != 0 {
		t.Fatalf("version after down: %d", v)
	}
	if err := db.Migrate(ctx, pool, latest); err != nil {
		t.Fatalf("up after down: %v", err)
	}
}
