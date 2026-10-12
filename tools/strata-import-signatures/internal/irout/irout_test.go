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

// An upstream id that differs only by a leading space keeps its own id
// across a save and reload (W08 review: " DVbot" was read back as "DVbot"
// and got a new id on every import).
func TestIDsKeepLeadingSpace(t *testing.T) {
	p := filepath.Join(t.TempDir(), "ids.txt")
	ids, _ := LoadIDs(p, 100, 109)
	plain, _ := ids.Get("DVbot")
	spaced, _ := ids.Get(" DVbot")
	if err := ids.Save("# test\n"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		again, err := LoadIDs(p, 100, 109)
		if err != nil {
			t.Fatal(err)
		}
		a, _ := again.Get("DVbot")
		b, _ := again.Get(" DVbot")
		if a != plain || b != spaced {
			t.Fatalf("reload %d: DVbot %d (want %d), \" DVbot\" %d (want %d)", i, a, plain, b, spaced)
		}
		if err := again.Save("# test\n"); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLiteral(t *testing.T) {
	for in, want := range map[string]string{"a.b*c": `a\.b\*c`, "\xff\x00x": `\xff\x00x`, "a b-c/d": "a b-c/d"} {
		if got := Literal(in); got != want || !RE2(got) {
			t.Errorf("Literal(%q) = %q, want %q", in, got, want)
		}
	}
}
