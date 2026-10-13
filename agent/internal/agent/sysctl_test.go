package agent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckDgramQlen(t *testing.T) {
	dir := t.TempDir()
	for _, c := range []struct {
		name, content string
		want          int
	}{
		{"set", "8192\n", 8192},
		{"kernel default (warns)", "512\n", 512},
		{"not a number", "lots\n", 0},
		{"negative", "-1\n", 0},
		{"empty", "", 0},
	} {
		p := filepath.Join(dir, c.name)
		if err := os.WriteFile(p, []byte(c.content), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := checkDgramQlen(p); got != c.want {
			t.Errorf("%s: got %d, want %d", c.name, got, c.want)
		}
	}
	if got := checkDgramQlen(filepath.Join(dir, "missing")); got != 0 {
		t.Errorf("missing file: got %d, want 0", got)
	}
}
