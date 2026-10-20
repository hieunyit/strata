package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// Inventory is diagnostic, untrusted node telemetry; it never grants permissions.
type Inventory struct {
	AgentVersion string   `json:"agent_version"`
	OS           string   `json:"operating_system"`
	ABI          uint32   `json:"abi_version"`
	Capabilities []string `json:"capabilities"`
}

var capabilityID = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{0,63}$`)

func (i Inventory) Validate() error {
	for _, value := range []string{i.AgentVersion, i.OS} {
		if len(value) > 128 || !utf8.ValidString(value) {
			return errors.New("inventory: invalid version or OS")
		}
		for _, r := range value {
			if r < 32 || r == 127 {
				return errors.New("inventory: control character")
			}
		}
	}
	if len(i.Capabilities) > 64 {
		return errors.New("inventory: too many capabilities")
	}
	for _, c := range i.Capabilities {
		if !capabilityID.MatchString(c) {
			return errors.New("inventory: invalid capability")
		}
	}
	return nil
}

func (s *Store) RecordInventory(ctx context.Context, node string, i Inventory, at time.Time) error {
	if err := i.Validate(); err != nil {
		return err
	}
	i.Capabilities = append([]string{}, i.Capabilities...)
	sort.Strings(i.Capabilities)
	raw, err := json.Marshal(i)
	if err != nil {
		return err
	}
	tag, err := s.pool.Exec(ctx, `UPDATE nodes SET inventory = $2, inventory_at = $3 WHERE id = $1 AND revoked_at IS NULL`, node, raw, at)
	if err != nil {
		return fmt.Errorf("store: inventory: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrNotFound
	}
	return nil
}

// CertificateStatus distinguishes missing evidence from a healthy certificate.
func CertificateStatus(expiry *time.Time, now time.Time) string {
	if expiry == nil {
		return "unknown"
	}
	if !expiry.After(now) {
		return "expired"
	}
	if !expiry.After(now.Add(7 * 24 * time.Hour)) {
		return "expiring"
	}
	return "healthy"
}

// ErrIncompatible is returned before any desired version or rollout is changed.
var ErrIncompatible = errors.New("store: incompatible nodes")

// CheckCapabilities is a preflight; CreateRollout rechecks transactionally.
func (s *Store) CheckCapabilities(ctx context.Context, required []string) error {
	if len(required) == 0 {
		return nil
	}
	nodes, err := s.ListNodes(ctx)
	if err != nil {
		return err
	}
	missing := []string{}
	for _, n := range nodes {
		if n.RevokedAt != nil {
			continue
		}
		have := map[string]bool{}
		for _, c := range n.Inventory.Capabilities {
			have[c] = true
		}
		for _, c := range required {
			if !have[c] {
				missing = append(missing, n.ID+":"+c)
			}
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("%w: %s", ErrIncompatible, strings.Join(missing, ", "))
	}
	return nil
}
