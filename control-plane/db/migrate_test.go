package db

import (
	"strings"
	"testing"
	"testing/fstest"
)

// The embedded files form a complete 1..n sequence with up and down.
func TestLoad(t *testing.T) {
	ms, err := load()
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) == 0 {
		t.Fatal("no migrations")
	}
	for i, m := range ms {
		if m.version != i+1 || m.up == "" || m.down == "" {
			t.Fatalf("migration %d: %+v", i, m.version)
		}
	}
}

// Two branches taking the same number (0008 twice, W12 integration):
// keyed by version alone, one of them was skipped without a word.
func TestLoadRejectsTwoMigrationsWithOneNumber(t *testing.T) {
	m := fstest.MapFS{}
	for _, n := range []string{"0001_init", "0002_secrets", "0002_kill_switch"} {
		m["migrations/"+n+".up.sql"] = &fstest.MapFile{Data: []byte("SELECT 1;")}
		m["migrations/"+n+".down.sql"] = &fstest.MapFile{Data: []byte("SELECT 1;")}
	}
	if _, err := loadFS(m); err == nil || !strings.Contains(err.Error(), "0002") {
		t.Fatalf("err = %v", err)
	}
}
