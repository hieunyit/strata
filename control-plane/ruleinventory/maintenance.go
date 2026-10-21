package ruleinventory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/strata/strata/control-plane/policy"
	"github.com/strata/strata/control-plane/store"
)

type Maintenance struct {
	Store      *store.Store
	ReplayKick func()
	Now        func() time.Time
	cursor     string
}

func (m *Maintenance) Run(ctx context.Context) {
	timer := time.NewTicker(time.Minute)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
			err := m.Once(bounded)
			cancel()
			if err != nil && ctx.Err() == nil {
				log.Print("[WARN] exception maintenance scan failed")
			}
		}
	}
}
func (m *Maintenance) Once(ctx context.Context) error {
	if err := m.Store.ReconcileExceptionMaintenance(ctx); err != nil {
		return err
	}
	now := time.Now().UTC()
	if m.Now != nil {
		now = m.Now().UTC()
	}
	candidates, err := m.Store.ExpiredExceptionCandidates(ctx, m.cursor, now)
	if err != nil {
		return err
	}
	for _, p := range candidates {
		approved, err := m.Store.GetPolicyVersion(ctx, p.ID, p.ApprovedVersion)
		if err != nil {
			return err
		}
		spec, err := policy.Parse(approved.Spec)
		if err != nil {
			return err
		}
		expired := []string{}
		for _, e := range spec.Exceptions {
			if e.ExpiresUnixMS <= now.UnixMilli() {
				expired = append(expired, e.ID)
			}
		}
		if len(expired) == 0 {
			continue
		}
		task, err := m.Store.QueueExceptionMaintenance(ctx, p.ID, approved.Version, p.Etag, expired)
		if err != nil {
			return err
		}
		if task.State != "pending" || m.ReplayKick == nil {
			continue
		}
		command, _ := json.Marshal(struct {
			Version int      `json:"source_version"`
			Expired []string `json:"expired_ids"`
		}{task.SourceVersion, task.ExpiredIDs})
		sum := sha256.Sum256([]byte(fmt.Sprintf("%s/%d", p.ID, task.SourceVersion)))
		a := store.Audit{Actor: "exception-maintenance", Subject: "system:exception-maintenance", Channel: "system", Action: "exceptions.expiryCleanup", Resource: "policies/" + p.ID, RequestID: "expiry-" + hex.EncodeToString(sum[:16])}
		// Crash recovery reads the committed receipt before looking at the current
		// revision, which may already be the maintenance draft or a later human edit.
		draft, err := m.Store.GetPolicyReplayEditResult(ctx, task.SourceEtag, command, a)
		if errors.Is(err, store.ErrNotFound) {
			if p.CurrentVersion != task.SourceVersion {
				continue
			}
			draft, err = m.Store.EditPolicyAndReplayOnce(ctx, p.ID, task.SourceEtag, command, a, func(before store.Policy) (json.RawMessage, error) {
				if before.CurrentVersion != task.SourceVersion || before.ApprovedVersion != task.SourceVersion {
					return nil, store.ErrEtagMismatch
				}
				return CleanupExpired(before.Spec, now)
			})
		}
		// The request fingerprint normally includes the concrete etag. Its durable
		// value is stored in the task, not reconstructed from later policy state.
		if errors.Is(err, store.ErrEtagMismatch) {
			continue
		}
		if err != nil {
			return err
		}
		if err := m.Store.CompleteExceptionMaintenance(ctx, task, draft.CurrentVersion); err != nil {
			return err
		}
		m.ReplayKick()
	}
	if len(candidates) == 100 {
		m.cursor = candidates[len(candidates)-1].ID
	} else {
		m.cursor = ""
	}
	return nil
}
func CleanupExpired(raw json.RawMessage, now time.Time) (json.RawMessage, error) {
	spec, err := policy.Parse(raw)
	if err != nil {
		return nil, err
	}
	keep := []policy.Exception{}
	for _, e := range spec.Exceptions {
		if e.ExpiresUnixMS > now.UnixMilli() {
			keep = append(keep, e)
		}
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}
	if len(keep) == 0 {
		delete(fields, "exceptions")
	} else {
		fields["exceptions"], err = json.Marshal(keep)
		if err != nil {
			return nil, err
		}
	}
	return json.Marshal(fields)
}
