// Package forceshadow applies the control plane's ForceShadow commands
// (nginx-module.md › Fallback; docs/design/control-file.md, force-shadow
// block): the agent keeps a deadline per policy (or for every policy) in a
// state file, so a restart neither loses nor extends it, and writes the
// policies still forced into the control file, which NGINX workers read
// within a second. Every second it writes the control file again if it
// differs: when a deadline passes, and when a bundle install created the
// file after the command came.
//
// The node fallback (package fallback) holds every policy in shadow with no
// deadline: only a ForceShadow command with clear for every policy, from
// the control plane, ends it (W12-G1-01).
package forceshadow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"sync"
	"time"

	fleetv1 "github.com/strata/strata/agent/gen/strata/fleet/v1"
	"github.com/strata/strata/agent/internal/bundles"
)

// MaxDuration of one command.
const MaxDuration = 24 * time.Hour

// State is what the state file holds: deadlines, and the node fallback's
// hold.
type State struct {
	All      time.Time            `json:"all,omitzero"`
	Policies map[string]time.Time `json:"policies,omitempty"`
	Fallback *Hold                `json:"fallback,omitempty"`
}

// Hold: the node fallback forced every policy into shadow.
type Hold struct {
	Reason string    `json:"reason"`
	Since  time.Time `json:"since"`
}

// Forced reports whether every policy is in shadow.
func (s State) Forced() bool { return !s.All.IsZero() || s.Fallback != nil }

// Manager owns the force-shadow block of one control file.
type Manager struct {
	control, state string
	now            func() time.Time

	mu sync.Mutex
	st State
}

// New loads the state file (a missing or unreadable one starts empty).
func New(controlFile, stateFile string) *Manager {
	m := &Manager{control: controlFile, state: stateFile, now: time.Now, st: State{Policies: map[string]time.Time{}}}
	b, err := os.ReadFile(stateFile)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		slog.Error("force shadow: state file", "err", err)
	default:
		var st State
		if err := json.Unmarshal(b, &st); err != nil {
			slog.Error("force shadow: state file is not valid; starting without force shadow", "err", err)
			break
		}
		for p := range st.Policies {
			if !bundles.ValidPolicyName(p) {
				delete(st.Policies, p)
			}
		}
		if st.Policies == nil {
			st.Policies = map[string]time.Time{}
		}
		m.st = st
	}
	return m
}

// Apply runs one ForceShadow command: the policy (or every policy) is in
// shadow until now + duration, replacing an earlier deadline, so a short
// duration also ends it early.
func (m *Manager) Apply(fs *fleetv1.ForceShadow) error {
	if fs.GetRoute() != "" {
		return errors.New("route not supported")
	}
	if fs.GetClear() {
		return m.clear(fs.GetPolicyId())
	}
	d := time.Duration(fs.GetDurationSeconds()) * time.Second
	if d <= 0 || d > MaxDuration {
		return errors.New("duration_seconds must be between 1 and 86400")
	}
	p := fs.GetPolicyId()
	if p != "" && !bundles.ValidPolicyName(p) {
		return fmt.Errorf("bad policy id %q", p)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	m.pruneLocked(now)
	until := now.Add(d)
	if p == "" {
		m.st.All = until
	} else {
		if _, ok := m.st.Policies[p]; !ok && len(m.st.Policies) >= bundles.MaxForcePolicies {
			return fmt.Errorf("at most %d policies can be forced at once", bundles.MaxForcePolicies)
		}
		m.st.Policies[p] = until
	}
	if err := m.saveLocked(); err != nil {
		return err
	}
	slog.Info("force shadow", "policy", p, "until", until.UTC().Format(time.RFC3339))
	err := m.reconcileLocked(now)
	if errors.Is(err, os.ErrNotExist) {
		return nil // no bundle yet: written once a bundle install creates the file
	}
	return err
}

// HoldAll forces every policy into shadow until a clear for every policy;
// a second hold keeps the first reason.
func (m *Manager) HoldAll(reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.st.Fallback != nil {
		return nil
	}
	m.st.Fallback = &Hold{Reason: reason, Since: m.now().UTC()}
	if err := m.saveLocked(); err != nil {
		m.st.Fallback = nil
		return err
	}
	err := m.reconcileLocked(m.now())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// clear ends the force shadow of policy now, or every one with "" (the
// fallback hold too).
func (m *Manager) clear(policy string) error {
	if policy != "" && !bundles.ValidPolicyName(policy) {
		return fmt.Errorf("bad policy id %q", policy)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if policy == "" {
		if h := m.st.Fallback; h != nil {
			slog.Warn("force shadow: node fallback lifted by the control plane", "reason", h.Reason, "since", h.Since.Format(time.RFC3339))
		}
		m.st = State{Policies: map[string]time.Time{}}
	} else {
		delete(m.st.Policies, policy)
	}
	if err := m.saveLocked(); err != nil {
		return err
	}
	slog.Info("force shadow cleared", "policy", policy)
	err := m.reconcileLocked(m.now())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// Snapshot returns the deadlines still running.
func (m *Manager) Snapshot() State {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruneLocked(m.now())
	out := State{All: m.st.All, Policies: map[string]time.Time{}}
	if h := m.st.Fallback; h != nil {
		out.Fallback = &Hold{Reason: h.Reason, Since: h.Since}
	}
	for p, t := range m.st.Policies {
		out.Policies[p] = t
	}
	return out
}

// Run keeps the control file in line with the deadlines until ctx ends.
func (m *Manager) Run(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		m.mu.Lock()
		err := m.reconcileLocked(m.now())
		m.mu.Unlock()
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			slog.Error("force shadow: control file", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (m *Manager) pruneLocked(now time.Time) bool {
	changed := false
	if !m.st.All.IsZero() && !now.Before(m.st.All) {
		m.st.All, changed = time.Time{}, true
	}
	for p, t := range m.st.Policies {
		if !now.Before(t) {
			delete(m.st.Policies, p)
			changed = true
		}
	}
	return changed
}

// reconcileLocked writes the control file when its block differs from the
// deadlines still running.
func (m *Manager) reconcileLocked(now time.Time) error {
	if m.pruneLocked(now) {
		if err := m.saveLocked(); err != nil {
			return err
		}
		slog.Info("force shadow: a deadline passed")
	}
	all := m.st.Forced()
	names := make([]string, 0, len(m.st.Policies))
	for p := range m.st.Policies {
		names = append(names, p)
	}
	sort.Strings(names)
	cur, err := bundles.ReadControl(m.control)
	if err != nil {
		return err
	}
	have := append([]string{}, cur.ForcePolicies...)
	sort.Strings(have)
	if cur.ForceAll == all && slices.Equal(have, names) {
		return nil
	}
	_, err = bundles.WriteForceShadow(m.control, all, names)
	return err
}

func (m *Manager) saveLocked() error {
	b, err := json.Marshal(m.st)
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
