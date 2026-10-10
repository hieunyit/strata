package db

import "testing"

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
