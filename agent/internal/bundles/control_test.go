package bundles

import (
	"crypto/sha256"
	"encoding/binary"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func inode(t *testing.T, p string) uint64 {
	t.Helper()
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return st.Sys().(*syscall.Stat_t).Ino
}

func TestControlCreateThenInPlace(t *testing.T) {
	p := filepath.Join(t.TempDir(), "control")
	sum := sha256.Sum256([]byte("one"))
	g, err := WriteControl(p, 1, sum, "bundle-1.sbn")
	if err != nil || g != 2 {
		t.Fatalf("create: %d %v", g, err)
	}
	ino := inode(t, p)
	sum2 := sha256.Sum256([]byte("two"))
	g, err = WriteControl(p, 2, sum2, "bundle-2.sbn")
	if err != nil || g != 4 {
		t.Fatalf("update: %d %v", g, err)
	}
	if inode(t, p) != ino {
		t.Fatal("the control file was replaced; workers map its inode")
	}
	c, err := ReadControl(p)
	if err != nil || c.Version != 2 || c.Name != "bundle-2.sbn" || c.SHA256 != sum2 || c.Generation != 4 {
		t.Fatalf("read back: %+v %v", c, err)
	}
	if st, _ := os.Stat(p); st.Size() != ControlSize {
		t.Fatalf("size %d", st.Size())
	}
}

// A crash between the odd and the even generation: the next write ends
// on an even generation above it.
func TestControlFinishesAnInterruptedWrite(t *testing.T) {
	p := filepath.Join(t.TempDir(), "control")
	if _, err := WriteControl(p, 1, [32]byte{}, "bundle-1.sbn"); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	binary.LittleEndian.PutUint64(b[16:], 5) // odd: being written
	_ = os.WriteFile(p, b, 0o644)
	g, err := WriteControl(p, 2, [32]byte{}, "bundle-2.sbn")
	if err != nil || g%2 != 0 || g <= 5 {
		t.Fatalf("generation %d %v", g, err)
	}
}

func TestControlRefusesBadNames(t *testing.T) {
	p := filepath.Join(t.TempDir(), "control")
	for _, n := range []string{"", ".", "..", "../x", "a/b", "sp ace"} {
		if _, err := WriteControl(p, 1, [32]byte{}, n); err == nil {
			t.Errorf("name %q accepted", n)
		}
	}
}

// The NGINX test fixture, written by mkbundle (Rust), reads back.
func TestControlReadsMkbundleOutput(t *testing.T) {
	c, err := ReadControl("../../../connectors/nginx/t/fixtures/bundle/control")
	if err != nil {
		t.Fatal(err)
	}
	if c.Version != 1 || c.Name != "bundle-1.sbn" || c.Generation != 2 {
		t.Fatalf("%+v", c)
	}
	data, _ := os.ReadFile("../../../connectors/nginx/t/fixtures/bundle/bundle-1.sbn")
	if sha256.Sum256(data) != c.SHA256 {
		t.Fatal("sha256 field does not match the fixture bundle")
	}
}
