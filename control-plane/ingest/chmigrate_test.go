package ingest

import (
	"strings"
	"testing"
)

func TestSplitSQLSchema(t *testing.T) {
	stmts := splitSQL(schemaSQL)
	if len(stmts) != 3 {
		t.Fatalf("%d statements", len(stmts))
	}
	for i, want := range []string{"CREATE TABLE IF NOT EXISTS events", "CREATE TABLE IF NOT EXISTS node_seq", "CREATE TABLE IF NOT EXISTS policy_requests"} {
		if !strings.HasPrefix(stmts[i], want) || strings.HasSuffix(stmts[i], ";") || strings.Contains(stmts[i], "--") {
			t.Errorf("statement %d: %.80q", i, stmts[i])
		}
	}
}

// The list is append-only and numbered from 1 without gaps.
func TestCHMigrationsNumbered(t *testing.T) {
	for i, m := range chMigrations {
		if m.version != uint32(i+1) || m.name == "" || m.up == nil {
			t.Fatalf("migration %d: %+v", i, m)
		}
	}
}
