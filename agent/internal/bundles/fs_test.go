package bundles

import (
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestCheckLocal(t *testing.T) {
	if err := CheckLocal(t.TempDir()); err != nil {
		t.Fatalf("local directory: %v", err)
	}
	defer func(f func(string, *unix.Statfs_t) error) { statfs = f }(statfs)
	for magic, name := range networkFS {
		statfs = func(_ string, st *unix.Statfs_t) error { st.Type = magic; return nil }
		err := CheckLocal("/var/lib/strata/bundles")
		if err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("%s: %v", name, err)
		}
		// and New refuses to start on it
		if _, err := New(nil, Options{Dir: t.TempDir(), ControlFile: t.TempDir() + "/c", PubKey: make([]byte, 32)}, nil); err == nil {
			t.Errorf("%s: manager started", name)
		}
	}
}
