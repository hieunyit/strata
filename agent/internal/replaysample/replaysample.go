// Package replaysample applies the control plane's SetReplaySampling
// (W12-N-01): the share of requests the NGINX workers sample for replay
// and the connector group's anonymization key. The key goes into
// replay.key in the bundle directory (written before the control file names
// it), the rate and key id into the control file's replay block
// (docs/design/control-file.md); workers apply them within a second.
//
// The agent keeps the setting in memory only: the control plane sends it
// whenever the node connects. Until then, after an agent restart, the
// files stay as they are, so a restart neither stops nor starts sampling.
// Every second the agent writes the block again if it differs, for example
// when a bundle install created the control file after the command came.
package replaysample

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	fleetv1 "github.com/strata/strata/agent/gen/strata/fleet/v1"
	"github.com/strata/strata/agent/internal/bundles"
)

// Setting in force; the key never leaves the manager.
type Setting struct {
	Rate  uint32 // basis points
	KeyID string
	key   []byte
}

// Manager owns the replay block of one control file.
type Manager struct {
	control, dir string

	mu  sync.Mutex
	cur *Setting // nil: not told since the agent started
}

// New manages controlFile and the key file in bundleDir.
func New(controlFile, bundleDir string) *Manager {
	return &Manager{control: controlFile, dir: bundleDir}
}

// Apply runs one SetReplaySampling.
func (m *Manager) Apply(c *fleetv1.SetReplaySampling) error {
	s := &Setting{Rate: c.GetRateBp()}
	if s.Rate > 10000 {
		return fmt.Errorf("rate_bp %d over 10000", s.Rate)
	}
	if s.Rate > 0 {
		if !bundles.ValidReplayKeyID(c.GetKeyId()) || len(c.GetKey()) != 32 {
			return errors.New("a key id of 1..16 [A-Za-z0-9._-] and a 32-byte key are required")
		}
		s.KeyID, s.key = c.GetKeyId(), append([]byte(nil), c.GetKey()...)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cur = s
	err := m.reconcileLocked()
	if errors.Is(err, os.ErrNotExist) {
		return nil // no bundle yet: written once a bundle install creates the file
	}
	if err == nil {
		slog.Info("replay sampling", "rate_bp", s.Rate, "key_id", s.KeyID)
	}
	return err
}

// Current returns the setting in force, nil before the first one.
func (m *Manager) Current() *Setting {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cur == nil {
		return nil
	}
	c := *m.cur
	c.key = nil
	return &c
}

// Run keeps the control file in line until ctx ends.
func (m *Manager) Run(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		m.mu.Lock()
		err := m.reconcileLocked()
		m.mu.Unlock()
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			slog.Error("replay sampling: control file", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (m *Manager) reconcileLocked() error {
	if m.cur == nil {
		return nil
	}
	cur, err := bundles.ReadControl(m.control)
	if err != nil {
		return err
	}
	keyFile := filepath.Join(m.dir, bundles.ReplayKeyFile)
	if m.cur.Rate == 0 {
		if cur.ReplayRate != 0 {
			if _, err := bundles.WriteReplay(m.control, 0, ""); err != nil {
				return err
			}
		}
		// no key left on disk once sampling is off
		if err := os.Remove(keyFile); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	if cur.ReplayRate == m.cur.Rate && cur.ReplayKeyID == m.cur.KeyID && keyFileHolds(keyFile, m.cur.KeyID) {
		return nil
	}
	// the key first: a worker reads it when the block names its id
	if err := bundles.WriteReplayKey(m.dir, m.cur.KeyID, m.cur.key); err != nil {
		return err
	}
	_, err = bundles.WriteReplay(m.control, m.cur.Rate, m.cur.KeyID)
	return err
}

func keyFileHolds(path, keyID string) bool {
	b, err := os.ReadFile(path)
	if err != nil || len(b) != 4+bundles.MaxReplayKeyID+32 || string(b[:4]) != "SRK1" {
		return false
	}
	id := b[4 : 4+bundles.MaxReplayKeyID]
	end := 0
	for end < len(id) && id[end] != 0 {
		end++
	}
	return string(id[:end]) == keyID
}
