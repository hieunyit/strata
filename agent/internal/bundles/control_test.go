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

// W07-G1-01: force-shadow is written in place (same inode, next even
// generation) and a later bundle switch keeps it.
func TestForceShadowSurvivesBundleSwitch(t *testing.T) {
	p := filepath.Join(t.TempDir(), "control")
	if _, err := WriteForceShadow(p, true, nil); !os.IsNotExist(err) {
		t.Fatalf("no control file yet: %v", err)
	}
	if _, err := WriteControl(p, 1, [32]byte{}, "bundle-1.sbn"); err != nil {
		t.Fatal(err)
	}
	ino := inode(t, p)
	g, err := WriteForceShadow(p, false, []string{"example-api", "example-web"})
	if err != nil || g != 4 {
		t.Fatalf("force shadow: %d %v", g, err)
	}
	if _, err := WriteControl(p, 2, [32]byte{}, "bundle-2.sbn"); err != nil {
		t.Fatal(err)
	}
	c, err := ReadControl(p)
	if err != nil || c.Name != "bundle-2.sbn" || c.ForceAll || len(c.ForcePolicies) != 2 || c.ForcePolicies[1] != "example-web" || c.Generation != 6 {
		t.Fatalf("%+v %v", c, err)
	}
	if inode(t, p) != ino {
		t.Fatal("control file replaced")
	}
	b, _ := os.ReadFile(p)
	if binary.LittleEndian.Uint32(b[324:]) != 0 || binary.LittleEndian.Uint32(b[328:]) != 2 || string(b[336:347]) != "example-api" || b[347] != 0 {
		t.Fatalf("layout: %x", b[324:400])
	}
	if _, err := WriteForceShadow(p, true, nil); err != nil {
		t.Fatal(err)
	}
	if c, _ := ReadControl(p); !c.ForceAll || len(c.ForcePolicies) != 0 || c.Name != "bundle-2.sbn" {
		t.Fatalf("%+v", c)
	}
	for _, bad := range [][]string{{"Example"}, {""}, {"a/b"}, {string(make([]byte, 56))}} {
		if _, err := WriteForceShadow(p, false, bad); err == nil {
			t.Errorf("policy %q accepted", bad)
		}
	}
	many := make([]string, MaxForcePolicies+1)
	for i := range many {
		many[i] = "p"
	}
	if _, err := WriteForceShadow(p, false, many); err == nil {
		t.Error("33 policies accepted")
	}
}

// W12-G1-02: the disabled-rules block is independent of the bundle and the
// force-shadow blocks, in place, at offset 2128.
func TestDisabledRulesBlock(t *testing.T) {
	p := filepath.Join(t.TempDir(), "control")
	if _, err := WriteDisabledRules(p, []uint32{1}); !os.IsNotExist(err) {
		t.Fatalf("no control file yet: %v", err)
	}
	if _, err := WriteControl(p, 1, [32]byte{}, "bundle-1.sbn"); err != nil {
		t.Fatal(err)
	}
	ino := inode(t, p)
	if _, err := WriteForceShadow(p, false, []string{"example-api"}); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteDisabledRules(p, []uint32{942100, 913100}); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteControl(p, 2, [32]byte{}, "bundle-2.sbn"); err != nil {
		t.Fatal(err)
	}
	c, err := ReadControl(p)
	if err != nil || c.Name != "bundle-2.sbn" || len(c.ForcePolicies) != 1 || len(c.DisabledRules) != 2 || c.DisabledRules[0] != 942100 {
		t.Fatalf("%+v %v", c, err)
	}
	b, _ := os.ReadFile(p)
	if binary.LittleEndian.Uint32(b[2128:]) != 2 || binary.LittleEndian.Uint32(b[2136:]) != 942100 || binary.LittleEndian.Uint32(b[2140:]) != 913100 {
		t.Fatalf("layout: %x", b[2128:2148])
	}
	if inode(t, p) != ino {
		t.Fatal("control file replaced")
	}
	if _, err := WriteDisabledRules(p, nil); err != nil {
		t.Fatal(err)
	}
	if c, _ := ReadControl(p); len(c.DisabledRules) != 0 || len(c.ForcePolicies) != 1 {
		t.Fatalf("%+v", c)
	}
	if _, err := WriteDisabledRules(p, make([]uint32, MaxDisabledRules+1)); err == nil {
		t.Fatal("481 rules accepted")
	}
	// a bad count in the file is refused on read
	binary.LittleEndian.PutUint32(b[2128:], MaxDisabledRules+1)
	_ = os.WriteFile(p, b, 0o644)
	if _, err := ReadControl(p); err == nil {
		t.Fatal("bad count read")
	}
}
