package store_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/strata/strata/control-plane/db"
	"github.com/strata/strata/control-plane/store"
)

// Against a real PostgreSQL (STRATA_TEST_POSTGRES_DSN): migration 0012,
// the replay sampling of a group (W12-N-01): a key made once and kept,
// a new one on rotation, never in the audit log; REPLAY_SYNC commands.
func TestReplaySamplingInPostgres(t *testing.T) {
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
		INSERT INTO nodes (id, group_id) VALUES ('node-a', 'edge'), ('node-c', 'lab')`); err != nil {
		t.Fatal(err)
	}
	s := store.New(pool)
	a := store.Audit{Actor: "alice", Channel: "api", Action: "SetReplaySampling", Resource: "groups/edge:setReplaySampling"}
	if r, err := s.NodeReplaySampling(ctx, "node-a"); err != nil || r.RateBp != 0 || r.Key != nil {
		t.Fatalf("before: %+v %v", r, err)
	}
	exp := time.Now().Add(time.Hour)
	r1, cmds, err := s.SetReplaySampling(ctx, "edge", 100, false,
		[]store.Command{{ID: "c1", NodeID: "node-a", Kind: store.CommandReplaySync, ExpiresAt: exp}}, a)
	if err != nil || r1.RateBp != 100 || len(r1.Key) != 32 || !strings.HasPrefix(r1.KeyID, "k") || len(r1.KeyID) > 16 || len(cmds) != 1 {
		t.Fatalf("set: %+v %v %v", r1, cmds, err)
	}
	r2, _, err := s.SetReplaySampling(ctx, "edge", 250, false, nil, a)
	if err != nil || r2.KeyID != r1.KeyID || string(r2.Key) != string(r1.Key) || r2.RateBp != 250 {
		t.Fatalf("same key kept: %+v %v", r2, err)
	}
	r3, _, err := s.SetReplaySampling(ctx, "edge", 250, true, nil, a)
	if err != nil || r3.KeyID == r1.KeyID || string(r3.Key) == string(r1.Key) {
		t.Fatalf("rotation: %+v %v", r3, err)
	}
	if r, err := s.NodeReplaySampling(ctx, "node-a"); err != nil || r.KeyID != r3.KeyID || string(r.Key) != string(r3.Key) {
		t.Fatalf("node: %+v %v", r, err)
	}
	if r, err := s.NodeReplaySampling(ctx, "node-c"); err != nil || r.RateBp != 0 {
		t.Fatalf("other group: %+v %v", r, err)
	}
	if g, err := s.GetReplaySampling(ctx, "lab"); err != store.ErrNotFound {
		t.Fatalf("lab: %+v %v", g, err)
	}
	// the key never in the audit log
	rows, err := pool.Query(ctx, `SELECT after::text FROM audit_log WHERE resource = 'groups/edge:setReplaySampling'`)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for rows.Next() {
		var after string
		if err := rows.Scan(&after); err != nil {
			t.Fatal(err)
		}
		n++
		for _, k := range [][]byte{r1.Key, r3.Key} {
			if strings.Contains(after, string(k)) || strings.Contains(after, "\"key\"") {
				t.Fatalf("key in the audit: %s", after)
			}
		}
	}
	if n != 3 {
		t.Fatalf("%d audit entries", n)
	}
	if err := db.Migrate(ctx, pool, 10); err != nil {
		t.Fatalf("down to 10: %v", err)
	}
	if err := db.Migrate(ctx, pool, latest); err != nil {
		t.Fatalf("up again: %v", err)
	}
}
