package irout

import (
	"os"
	"path/filepath"
	"testing"
)

// Ids given once are kept; new upstream rules get the next free id.
func TestIDsAreKept(t *testing.T) {
	p := filepath.Join(t.TempDir(), "ids.txt")
	ids, _ := LoadIDs(p, 100, 102)
	a, _ := ids.Get("rule a")
	b, _ := ids.Get("b")
	if a != 100 || b != 101 {
		t.Fatalf("%d %d", a, b)
	}
	if err := ids.Save("# test\n"); err != nil {
		t.Fatal(err)
	}
	again, err := LoadIDs(p, 100, 102)
	if err != nil {
		t.Fatal(err)
	}
	if x, _ := again.Get("b"); x != 101 {
		t.Fatalf("b got %d after reload", x)
	}
	if c, _ := again.Get("c"); c != 102 {
		t.Fatalf("c got %d", c)
	}
	if _, err := again.Get("d"); err == nil {
		t.Fatal("range exhausted but an id was given")
	}
	_ = os.WriteFile(p, []byte("x 999\n"), 0o644)
	if _, err := LoadIDs(p, 100, 102); err == nil {
		t.Fatal("id out of range accepted")
	}
}

func TestLiteral(t *testing.T) {
	for in, want := range map[string]string{"a.b*c": `a\.b\*c`, "\xff\x00x": `\xff\x00x`, "a b-c/d": "a b-c/d"} {
		if got := Literal(in); got != want || !RE2(got) {
			t.Errorf("Literal(%q) = %q, want %q", in, got, want)
		}
	}
}
