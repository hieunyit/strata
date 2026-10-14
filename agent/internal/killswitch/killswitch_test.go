package killswitch

import (
	"path/filepath"
	"slices"
	"testing"

	fleetv1 "github.com/strata/strata/agent/gen/strata/fleet/v1"
	"github.com/strata/strata/agent/internal/bundles"
)

func control(t *testing.T, p string) []uint32 {
	t.Helper()
	c, err := bundles.ReadControl(p)
	if err != nil {
		t.Fatal(err)
	}
	return c.DisabledRules
}

func TestDisableEnableAndRestart(t *testing.T) {
	dir := t.TempDir()
	ctl, st := filepath.Join(dir, "control"), filepath.Join(dir, "disabled-rules.json")
	if _, err := bundles.WriteControl(ctl, 1, [32]byte{}, "bundle-1.sbn"); err != nil {
		t.Fatal(err)
	}
	m := New(ctl, st)
	if err := m.Disable(&fleetv1.DisableRules{RuleIds: []uint32{942100, 913100, 942100}}); err != nil {
		t.Fatal(err)
	}
	if err := m.Disable(&fleetv1.DisableRules{RuleIds: []uint32{941100}}); err != nil {
		t.Fatal(err)
	}
	want := []uint32{913100, 941100, 942100}
	if !slices.Equal(m.Rules(), want) || !slices.Equal(control(t, ctl), want) {
		t.Fatalf("%v %v", m.Rules(), control(t, ctl))
	}
	// a restart keeps the rules off
	if got := New(ctl, st).Rules(); !slices.Equal(got, want) {
		t.Fatalf("after restart %v", got)
	}
	if err := m.Enable(&fleetv1.EnableRules{RuleIds: []uint32{941100, 1}}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(control(t, ctl), []uint32{913100, 942100}) {
		t.Fatalf("%v", control(t, ctl))
	}
	// replace: the control plane's list
	if err := m.Disable(&fleetv1.DisableRules{RuleIds: []uint32{920170}, Replace: true}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(control(t, ctl), []uint32{920170}) {
		t.Fatalf("%v", control(t, ctl))
	}
	if err := m.Enable(&fleetv1.EnableRules{All: true}); err != nil {
		t.Fatal(err)
	}
	if len(control(t, ctl)) != 0 || len(New(ctl, st).Rules()) != 0 {
		t.Fatal("all not enabled")
	}
}

func TestRefusals(t *testing.T) {
	dir := t.TempDir()
	ctl := filepath.Join(dir, "control")
	_, _ = bundles.WriteControl(ctl, 1, [32]byte{}, "bundle-1.sbn")
	m := New(ctl, filepath.Join(dir, "s.json"))
	for _, d := range []*fleetv1.DisableRules{{}, {RuleIds: []uint32{0}}} {
		if err := m.Disable(d); err == nil {
			t.Errorf("%v accepted", d)
		}
	}
	many := make([]uint32, bundles.MaxDisabledRules+1)
	for i := range many {
		many[i] = uint32(i + 1)
	}
	if err := m.Disable(&fleetv1.DisableRules{RuleIds: many}); err == nil {
		t.Fatal("481 rules accepted")
	}
	if len(m.Rules()) != 0 {
		t.Fatalf("a refused command changed the list: %v", m.Rules())
	}
	if err := m.Enable(&fleetv1.EnableRules{}); err == nil {
		t.Fatal("empty enable accepted")
	}
}

// the command came before the first bundle: written once the control file
// exists
func TestBeforeTheFirstBundle(t *testing.T) {
	dir := t.TempDir()
	ctl := filepath.Join(dir, "control")
	m := New(ctl, filepath.Join(dir, "s.json"))
	if err := m.Disable(&fleetv1.DisableRules{RuleIds: []uint32{942100}}); err != nil {
		t.Fatal(err)
	}
	if _, err := bundles.WriteControl(ctl, 1, [32]byte{}, "bundle-1.sbn"); err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	err := m.reconcileLocked()
	m.mu.Unlock()
	if err != nil || !slices.Equal(control(t, ctl), []uint32{942100}) {
		t.Fatalf("%v %v", err, control(t, ctl))
	}
}
