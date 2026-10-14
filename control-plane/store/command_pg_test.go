package store_test

import (
	"context"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/strata/strata/control-plane/db"
	"github.com/strata/strata/control-plane/store"
)

// Against a real PostgreSQL (STRATA_TEST_POSTGRES_DSN, an empty database):
// migration 0008 and the kill-switch commands with their rule IDs
// (W12-G1-02), then down to 0007 and up again.
func TestKillSwitchCommandsInPostgres(t *testing.T) {
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
	if _, err := pool.Exec(ctx, `INSERT INTO connector_groups (id, name) VALUES ('edge', 'Edge');
		INSERT INTO nodes (id, group_id) VALUES ('node-a', 'edge'), ('node-b', 'edge')`); err != nil {
		t.Fatal(err)
	}
	s := store.New(pool)
	exp := time.Now().Add(time.Minute)
	got, err := s.CreateCommands(ctx, []store.Command{
		{ID: "c1", NodeID: "node-a", Kind: store.CommandDisableRules, RuleIDs: []int32{942100, 913100}, ExpiresAt: exp},
		{ID: "c2", NodeID: "node-b", Kind: store.CommandEnableRules, ExpiresAt: exp},
	}, store.Audit{Actor: "alice", Channel: "api", Action: "test", Resource: "rules/942100"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got[0].RuleIDs, []int32{942100, 913100}) || len(got[1].RuleIDs) != 0 {
		t.Fatalf("%+v", got)
	}
	pend, err := s.PendingCommands(ctx, []string{"node-a", "node-b"}, time.Now())
	if err != nil || len(pend) != 2 || pend[0].Kind != store.CommandDisableRules || pend[0].RuleIDs[1] != 913100 {
		t.Fatalf("%+v %v", pend, err)
	}
	// 481 rule IDs: refused by the table
	many := make([]int32, 481)
	if _, err := s.CreateCommands(ctx, []store.Command{{ID: "c3", NodeID: "node-a", Kind: store.CommandSetRules, RuleIDs: many, ExpiresAt: exp}},
		store.Audit{Actor: "alice", Channel: "api", Action: "test"}); err == nil {
		t.Fatal("481 rule ids stored")
	}
	if err := db.Migrate(ctx, pool, 7); err != nil {
		t.Fatalf("down to 7: %v", err)
	}
	if err := db.Migrate(ctx, pool, latest); err != nil {
		t.Fatalf("up again: %v", err)
	}
}
