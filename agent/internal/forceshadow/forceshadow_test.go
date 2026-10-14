package forceshadow

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	fleetv1 "github.com/strata/strata/agent/gen/strata/fleet/v1"
	"github.com/strata/strata/agent/internal/bundles"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func setup(t *testing.T) (dir string, m *Manager, c *clock) {
	t.Helper()
	dir = t.TempDir()
	c = &clock{t: time.Date(2026, 10, 12, 8, 0, 0, 0, time.UTC)}
	m = New(filepath.Join(dir, "control"), filepath.Join(dir, "force-shadow.json"))
	m.now = c.now
	return dir, m, c
}

func control(t *testing.T, dir string) bundles.Control {
	t.Helper()
	ctl, err := bundles.ReadControl(filepath.Join(dir, "control"))
	if err != nil {
		t.Fatal(err)
	}
	return ctl
}

func fs(policy string, secs uint32) *fleetv1.ForceShadow {
	return &fleetv1.ForceShadow{PolicyId: policy, DurationSeconds: secs}
}

func TestApplyWritesTheControlFileAndExpires(t *testing.T) {
	dir, m, c := setup(t)
	if _, err := bundles.WriteControl(filepath.Join(dir, "control"), 1, [32]byte{}, "bundle-1.sbn"); err != nil {
		t.Fatal(err)
	}
	if err := m.Apply(fs("example-api", 60)); err != nil {
		t.Fatal(err)
	}
	if err := m.Apply(fs("", 30)); err != nil {
		t.Fatal(err)
	}
	ctl := control(t, dir)
	if !ctl.ForceAll || len(ctl.ForcePolicies) != 1 || ctl.ForcePolicies[0] != "example-api" {
		t.Fatalf("%+v", ctl)
	}
	gen := ctl.Generation
	m.mu.Lock()
	_ = m.reconcileLocked(c.now())
	m.mu.Unlock()
	if control(t, dir).Generation != gen {
		t.Fatal("rewritten although nothing changed")
	}
	c.add(31 * time.Second)
	m.mu.Lock()
	_ = m.reconcileLocked(c.now())
	m.mu.Unlock()
	if ctl := control(t, dir); ctl.ForceAll || len(ctl.ForcePolicies) != 1 {
		t.Fatalf("after 31 s: %+v", ctl)
	}
	// A shorter command ends it early.
	if err := m.Apply(fs("example-api", 1)); err != nil {
		t.Fatal(err)
	}
	c.add(time.Second)
	m.mu.Lock()
	_ = m.reconcileLocked(c.now())
	m.mu.Unlock()
	if ctl := control(t, dir); ctl.ForceAll || len(ctl.ForcePolicies) != 0 || ctl.Name != "bundle-1.sbn" {
		t.Fatalf("after expiry: %+v", ctl)
	}
}

// The deadline survives a restart of the agent, and is not extended by it.
func TestDeadlineSurvivesRestart(t *testing.T) {
	dir, m, c := setup(t)
	if err := m.Apply(fs("example-web", 120)); err != nil { // no control file yet: kept for later
		t.Fatal(err)
	}
	m2 := New(filepath.Join(dir, "control"), filepath.Join(dir, "force-shadow.json"))
	m2.now = c.now
	if until := m2.Snapshot().Policies["example-web"]; !until.Equal(c.now().Add(120 * time.Second)) {
		t.Fatalf("after restart: %v", until)
	}
	// A bundle install creates the control file: the next tick writes it.
	if _, err := bundles.WriteControl(filepath.Join(dir, "control"), 1, [32]byte{}, "bundle-1.sbn"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m2.Run(ctx); close(done) }()
	deadline := time.Now().Add(3 * time.Second)
	for len(control(t, dir).ForcePolicies) != 1 {
		if time.Now().After(deadline) {
			t.Fatal("not written after the control file appeared")
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done
	c.add(121 * time.Second)
	m3 := New(filepath.Join(dir, "control"), filepath.Join(dir, "force-shadow.json"))
	m3.now = c.now
	if len(m3.Snapshot().Policies) != 0 {
		t.Fatal("expired deadline came back after a restart")
	}
}

func TestApplyRefuses(t *testing.T) {
	dir, m, _ := setup(t)
	for _, f := range []*fleetv1.ForceShadow{
		{PolicyId: "example-api", Route: "/login", DurationSeconds: 60},
		fs("example-api", 0),
		fs("example-api", 86401),
		fs("Example API", 60),
		fs("../x", 60),
	} {
		if err := m.Apply(f); err == nil {
			t.Errorf("%v accepted", f)
		}
	}
	if err := m.Apply(&fleetv1.ForceShadow{Route: "/login", DurationSeconds: 60}); err == nil || err.Error() != "route not supported" {
		t.Errorf("route: %v", err)
	}
	for i := range bundles.MaxForcePolicies {
		if err := m.Apply(fs("p"+string(rune('a'+i%26))+string(rune('a'+i/26)), 60)); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.Apply(fs("one-too-many", 60)); err == nil {
		t.Error("33rd policy accepted")
	}
	if _, err := os.Stat(filepath.Join(dir, "control")); !os.IsNotExist(err) {
		t.Error("a control file was created by a command")
	}
	// A corrupt state file starts empty.
	_ = os.WriteFile(filepath.Join(dir, "force-shadow.json"), []byte("{"), 0o600)
	if s := New(filepath.Join(dir, "control"), filepath.Join(dir, "force-shadow.json")).Snapshot(); len(s.Policies) != 0 || !s.All.IsZero() {
		t.Fatalf("corrupt state: %+v", s)
	}
}

// A clear ends a force shadow before its deadline: one policy, or all.
func TestClear(t *testing.T) {
	dir, m, _ := setup(t)
	if _, err := bundles.WriteControl(filepath.Join(dir, "control"), 1, [32]byte{}, "bundle-1.sbn"); err != nil {
		t.Fatal(err)
	}
	for _, f := range []*fleetv1.ForceShadow{fs("example-api", 600), fs("example-web", 600), fs("", 600)} {
		if err := m.Apply(f); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.Apply(&fleetv1.ForceShadow{PolicyId: "example-api", Clear: true}); err != nil {
		t.Fatal(err)
	}
	if ctl := control(t, dir); !ctl.ForceAll || len(ctl.ForcePolicies) != 1 || ctl.ForcePolicies[0] != "example-web" {
		t.Fatalf("after clearing one: %+v", ctl)
	}
	if err := m.Apply(&fleetv1.ForceShadow{Clear: true}); err != nil {
		t.Fatal(err)
	}
	if ctl := control(t, dir); ctl.ForceAll || len(ctl.ForcePolicies) != 0 {
		t.Fatalf("after clearing all: %+v", ctl)
	}
	if s := New(filepath.Join(dir, "control"), filepath.Join(dir, "force-shadow.json")).Snapshot(); !s.All.IsZero() || len(s.Policies) != 0 {
		t.Fatalf("cleared state not saved: %+v", s)
	}
	if err := m.Apply(&fleetv1.ForceShadow{PolicyId: "Bad Name", Clear: true}); err == nil {
		t.Fatal("bad policy accepted")
	}
}

// W12-G1-01: the node fallback's hold has no deadline and survives a
// restart; a command's deadline passing, a per-policy clear or another
// hold do not end it; only a clear for every policy does.
func TestFallbackHoldOnlyEndsOnClearAll(t *testing.T) {
	dir, m, c := setup(t)
	if _, err := bundles.WriteControl(filepath.Join(dir, "control"), 1, [32]byte{}, "bundle-1.sbn"); err != nil {
		t.Fatal(err)
	}
	if err := m.HoldAll("block_rate"); err != nil {
		t.Fatal(err)
	}
	if err := m.HoldAll("budget"); err != nil {
		t.Fatal(err)
	}
	if ctl := control(t, dir); !ctl.ForceAll {
		t.Fatalf("not forced: %+v", ctl)
	}
	if h := m.Snapshot().Fallback; h == nil || h.Reason != "block_rate" || !h.Since.Equal(c.now()) {
		t.Fatalf("hold %+v", h)
	}
	// a command for every policy expires; one policy is cleared
	for _, f := range []*fleetv1.ForceShadow{fs("", 60), fs("example-api", 60), {PolicyId: "example-api", Clear: true}} {
		if err := m.Apply(f); err != nil {
			t.Fatal(err)
		}
	}
	c.add(48 * time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m.Run(ctx); close(done) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done
	if ctl := control(t, dir); !ctl.ForceAll || len(ctl.ForcePolicies) != 0 {
		t.Fatalf("after 48 h: %+v", ctl)
	}
	// restart
	m2 := New(filepath.Join(dir, "control"), filepath.Join(dir, "force-shadow.json"))
	m2.now = c.now
	if s := m2.Snapshot(); s.Fallback == nil || s.Fallback.Reason != "block_rate" || !s.Forced() {
		t.Fatalf("after restart: %+v", s)
	}
	if err := m2.Apply(&fleetv1.ForceShadow{Clear: true}); err != nil {
		t.Fatal(err)
	}
	if ctl := control(t, dir); ctl.ForceAll {
		t.Fatalf("after clear: %+v", ctl)
	}
	if s := New(filepath.Join(dir, "control"), filepath.Join(dir, "force-shadow.json")).Snapshot(); s.Forced() {
		t.Fatalf("clear not saved: %+v", s)
	}
	// no control file yet: the hold is kept and written later
	dir2, m3, _ := setup(t)
	if err := m3.HoldAll("engine_errors"); err != nil {
		t.Fatal(err)
	}
	if _, err := bundles.WriteControl(filepath.Join(dir2, "control"), 1, [32]byte{}, "bundle-1.sbn"); err != nil {
		t.Fatal(err)
	}
	m3.mu.Lock()
	err := m3.reconcileLocked(m3.now())
	m3.mu.Unlock()
	if err != nil || !control(t, dir2).ForceAll {
		t.Fatalf("written later: %v", err)
	}
}
