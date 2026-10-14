package replaysample

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	fleetv1 "github.com/strata/strata/agent/gen/strata/fleet/v1"
	"github.com/strata/strata/agent/internal/bundles"
)

var key = bytes.Repeat([]byte{0x5a}, 32)

func control(t *testing.T, p string) bundles.Control {
	t.Helper()
	c, err := bundles.ReadControl(p)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// W12-N-01: the key file first, then the control file names it; off
// removes the key from the disk; an agent restart changes nothing until the
// control plane tells it again.
func TestApplyWritesKeyThenBlock(t *testing.T) {
	dir := t.TempDir()
	ctl := filepath.Join(dir, "control")
	if _, err := bundles.WriteControl(ctl, 1, [32]byte{}, "bundle-1.sbn"); err != nil {
		t.Fatal(err)
	}
	m := New(ctl, dir)
	if m.Current() != nil {
		t.Fatal("a setting before the control plane said one")
	}
	if err := m.Apply(&fleetv1.SetReplaySampling{RateBp: 100, KeyId: "kq7v2", Key: key}); err != nil {
		t.Fatal(err)
	}
	c := control(t, ctl)
	if c.ReplayRate != 100 || c.ReplayKeyID != "kq7v2" {
		t.Fatalf("block %+v", c)
	}
	b, err := os.ReadFile(filepath.Join(dir, bundles.ReplayKeyFile))
	if err != nil || len(b) != 52 || string(b[:4]) != "SRK1" || string(b[4:9]) != "kq7v2" || b[9] != 0 || !bytes.Equal(b[20:], key) {
		t.Fatalf("key file %x %v", b, err)
	}
	if fi, _ := os.Stat(filepath.Join(dir, bundles.ReplayKeyFile)); fi.Mode().Perm() != 0o640 {
		t.Fatalf("mode %v", fi.Mode())
	}
	if s := m.Current(); s.Rate != 100 || s.KeyID != "kq7v2" || s.key != nil {
		t.Fatalf("current %+v", s)
	}
	// the other blocks are untouched
	if c.Name != "bundle-1.sbn" || c.Generation%2 != 0 {
		t.Fatalf("control %+v", c)
	}

	// restart: nothing changes before the control plane speaks
	m2 := New(ctl, dir)
	m2.mu.Lock()
	if err := m2.reconcileLocked(); err != nil {
		t.Fatal(err)
	}
	m2.mu.Unlock()
	if c := control(t, ctl); c.ReplayRate != 100 {
		t.Fatalf("a restart changed the block: %+v", c)
	}

	// a new control file (bundle install): written again
	if err := os.Remove(ctl); err != nil {
		t.Fatal(err)
	}
	if _, err := bundles.WriteControl(ctl, 2, [32]byte{}, "bundle-2.sbn"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m.Run(ctx); close(done) }()
	deadline := time.Now().Add(3 * time.Second)
	for control(t, ctl).ReplayRate != 100 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done
	if c := control(t, ctl); c.ReplayRate != 100 || c.ReplayKeyID != "kq7v2" {
		t.Fatalf("not written again: %+v", c)
	}

	// off: block cleared, key gone
	if err := m.Apply(&fleetv1.SetReplaySampling{}); err != nil {
		t.Fatal(err)
	}
	if c := control(t, ctl); c.ReplayRate != 0 || c.ReplayKeyID != "" {
		t.Fatalf("off: %+v", c)
	}
	if _, err := os.Stat(filepath.Join(dir, bundles.ReplayKeyFile)); !os.IsNotExist(err) {
		t.Fatalf("key left on disk: %v", err)
	}
}

func TestApplyRefuses(t *testing.T) {
	dir := t.TempDir()
	ctl := filepath.Join(dir, "control")
	m := New(ctl, dir)
	for _, c := range []*fleetv1.SetReplaySampling{
		{RateBp: 10001, KeyId: "k1", Key: key},
		{RateBp: 100, KeyId: "", Key: key},
		{RateBp: 100, KeyId: "bad id", Key: key},
		{RateBp: 100, KeyId: "k1", Key: key[:31]},
		{RateBp: 100, KeyId: "a-key-id-longer-than-16", Key: key},
	} {
		if err := m.Apply(c); err == nil {
			t.Errorf("%v accepted", c)
		}
	}
	// no control file yet: kept, written later
	if err := m.Apply(&fleetv1.SetReplaySampling{RateBp: 1, KeyId: "k1", Key: key}); err != nil {
		t.Fatal(err)
	}
}
