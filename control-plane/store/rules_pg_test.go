package store_test

import (
	"context"
	"errors"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/strata/strata/control-plane/db"
	"github.com/strata/strata/control-plane/store"
)

// Against a real PostgreSQL (STRATA_TEST_POSTGRES_DSN, an empty database):
// migration 0010, the per-group disabled rules with their commands and
// audit entry (W12-G2-02), then down to 0008 and up again.
func TestDisabledRulesInPostgres(t *testing.T) {
	dsn := os.Getenv("STRATA_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("STRATA_TEST_POSTGRES_DSN not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close) // after the migration back to 0 below
	latest, err := db.Latest()
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(ctx, pool, latest); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Migrate(context.Background(), pool, 0) })
	if _, err := pool.Exec(ctx, `INSERT INTO connector_groups (id, name) VALUES ('edge', 'Edge'), ('lab', 'Lab');
		INSERT INTO nodes (id, group_id) VALUES ('node-a', 'edge'), ('node-b', 'edge'), ('node-c', 'lab')`); err != nil {
		t.Fatal(err)
	}
	s := store.New(pool)
	exp := time.Now().Add(time.Minute)
	a := store.Audit{Actor: "alice", Channel: "api", Action: "EmergencyDisableRule", Resource: "groups/edge/rules/942100"}
	cmds := []store.Command{
		{ID: "c1", NodeID: "node-a", Kind: store.CommandDisableRules, RuleIDs: []int32{942100}, ExpiresAt: exp},
		{ID: "c2", NodeID: "node-b", Kind: store.CommandDisableRules, RuleIDs: []int32{942100}, ExpiresAt: exp},
	}
	row, out, err := s.SetRuleDisabled(ctx, "edge", 942100, true, "FP on /search", cmds, a)
	if err != nil || row.RuleID != 942100 || row.CreatedBy != "alice" || len(out) != 2 || out[1].RuleIDs[0] != 942100 {
		t.Fatalf("%+v %+v %v", row, out, err)
	}
	// again: the reason is updated, no second row
	if _, _, err := s.SetRuleDisabled(ctx, "edge", 942100, true, "FP on /search and /find", nil, a); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.SetRuleDisabled(ctx, "edge", 913100, true, "scanner FP", nil, a); err != nil {
		t.Fatal(err)
	}
	rows, err := s.DisabledRules(ctx, "edge")
	if err != nil || len(rows) != 2 || rows[1].Reason != "FP on /search and /find" {
		t.Fatalf("%+v %v", rows, err)
	}
	if ids, err := s.NodeDisabledRules(ctx, "node-b"); err != nil || !slices.Equal(ids, []int32{913100, 942100}) {
		t.Fatalf("node-b %v %v", ids, err)
	}
	if ids, err := s.NodeDisabledRules(ctx, "node-c"); err != nil || len(ids) != 0 {
		t.Fatalf("another group: %v %v", ids, err)
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE actor = 'alice' AND resource = 'groups/edge/rules/942100'
		AND after->>'reason' <> '' AND after->>'group_id' = 'edge' AND (after->>'rule_id')::int = 942100`).Scan(&n); err != nil || n != 2 {
		t.Fatalf("audit entries %d %v", n, err)
	}
	// a reason is required by the table too
	if _, _, err := s.SetRuleDisabled(ctx, "edge", 941100, true, "", nil, a); err == nil {
		t.Fatal("empty reason stored")
	}
	// an unknown group
	if _, _, err := s.SetRuleDisabled(ctx, "nope", 941100, true, "x", nil, a); err == nil {
		t.Fatal("unknown group stored")
	}
	// enable
	if _, _, err := s.SetRuleDisabled(ctx, "edge", 942100, false, "fixed", nil, a); err != nil {
		t.Fatal(err)
	}
	if ids, _ := s.NodeDisabledRules(ctx, "node-a"); !slices.Equal(ids, []int32{913100}) {
		t.Fatalf("after enable %v", ids)
	}
	// the limit of a node's control file
	if _, err := pool.Exec(ctx, `INSERT INTO disabled_rules (group_id, rule_id, reason, created_by)
		SELECT 'lab', g, 'bulk', 'alice' FROM generate_series(1, 480) g`); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.SetRuleDisabled(ctx, "lab", 999999, true, "one more", nil, a); !errors.Is(err, store.ErrTooManyRules) {
		t.Fatalf("481st rule: %v", err)
	}
	if _, _, err := s.SetRuleDisabled(ctx, "lab", 480, true, "same rule, new reason", nil, a); err != nil {
		t.Fatalf("updating one of 480: %v", err)
	}
	if err := db.Migrate(ctx, pool, 8); err != nil {
		t.Fatalf("down to 8: %v", err)
	}
	if err := db.Migrate(ctx, pool, latest); err != nil {
		t.Fatalf("up again: %v", err)
	}
}
