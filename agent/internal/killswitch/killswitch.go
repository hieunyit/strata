// Package killswitch applies the control plane's DisableRules and
// EnableRules commands (W12-G1-02, nginx-module.md › Tắt rule khẩn cấp):
// the agent keeps the rules switched off on this node in a state file, so
// that a restart keeps them off, and writes the list into the control file
// (docs/design/control-file.md, disabled-rules block), which the NGINX
// workers read within a second. Every second it writes the block again if
// it differs, for example when a bundle install created the control file
// after the command came. A rule stays off until EnableRules.
package killswitch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	fleetv1 "github.com/strata/strata/agent/gen/strata/fleet/v1"
	"github.com/strata/strata/agent/internal/bundles"
)

// State is what the state file holds.
type State struct {
	Rules []uint32 `json:"rules"`
}

// Manager owns the disabled-rules block of one control file.
type Manager struct {
	control, state string

	mu    sync.Mutex
	rules []uint32 // sorted, unique
}

// New loads the state file (a missing or unreadable one starts empty).
func New(controlFile, stateFile string) *Manager {
	m := &Manager{control: controlFile, state: stateFile}
	b, err := os.ReadFile(stateFile)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		slog.Error("kill switch: state file", "err", err)
	default:
		var st State
		if err := json.Unmarshal(b, &st); err != nil || len(st.Rules) > bundles.MaxDisabledRules {
			slog.Error("kill switch: state file is not valid; starting with every rule on", "err", err)
			break
		}
		m.rules = normalize(st.Rules)
	}
	return m
}

func normalize(ids []uint32) []uint32 {
	out := slices.Clone(ids)
	slices.Sort(out)
	return slices.Compact(out)
}

// Disable runs one DisableRules command.
func (m *Manager) Disable(d *fleetv1.DisableRules) error {
	ids := d.GetRuleIds()
	if len(ids) == 0 && !d.GetReplace() {
		return errors.New("no rule_ids")
	}
	for _, id := range ids {
		if id == 0 {
			return errors.New("rule id 0")
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	next := ids
	if !d.GetReplace() {
		next = append(slices.Clone(m.rules), ids...)
	}
	next = normalize(next)
	if len(next) > bundles.MaxDisabledRules {
		return fmt.Errorf("at most %d rules can be disabled on a node", bundles.MaxDisabledRules)
	}
	return m.setLocked(next)
}

// Enable runs one EnableRules command.
func (m *Manager) Enable(e *fleetv1.EnableRules) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e.GetAll() {
		return m.setLocked(nil)
	}
	if len(e.GetRuleIds()) == 0 {
		return errors.New("no rule_ids (all: true enables every rule)")
	}
	next := slices.DeleteFunc(slices.Clone(m.rules), func(id uint32) bool {
		return slices.Contains(e.GetRuleIds(), id)
	})
	return m.setLocked(next)
}

func (m *Manager) setLocked(next []uint32) error {
	prev := m.rules
	m.rules = next
	if err := m.saveLocked(); err != nil {
		m.rules = prev
		return err
	}
	slog.Warn("kill switch: disabled rules", "rules", next)
	err := m.reconcileLocked()
	if errors.Is(err, os.ErrNotExist) {
		return nil // no bundle yet: written once a bundle install creates the file
	}
	return err
}

// Rules returns the rules switched off, sorted.
func (m *Manager) Rules() []uint32 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.rules)
}

// Run keeps the control file in line with the list until ctx ends.
func (m *Manager) Run(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		m.mu.Lock()
		err := m.reconcileLocked()
		m.mu.Unlock()
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			slog.Error("kill switch: control file", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (m *Manager) reconcileLocked() error {
	cur, err := bundles.ReadControl(m.control)
	if err != nil {
		return err
	}
	if slices.Equal(normalize(cur.DisabledRules), m.rules) {
		return nil
	}
	_, err = bundles.WriteDisabledRules(m.control, m.rules)
	return err
}

func (m *Manager) saveLocked() error {
	b, err := json.Marshal(State{Rules: m.rules})
	if err != nil {
		return err
	}
	tmp := filepath.Join(filepath.Dir(m.state), "."+filepath.Base(m.state)+".new")
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, m.state)
}
