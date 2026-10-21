package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// UpdatePolicyOnce creates one draft version for a durable actor/request_id.
// The replayable response, policy version and audit commit atomically. A delayed
// retry returns the original result even after later policy edits. Reuse with a
// different command is rejected. The caller must validate the spec and permissions.
func (s *Store) UpdatePolicyOnce(ctx context.Context, id, etag string, spec json.RawMessage, a Audit) (Policy, error) {
	if len(spec) > 256*1024 || !json.Valid(spec) {
		return Policy{}, fmt.Errorf("store: invalid policy spec")
	}
	spec = append(json.RawMessage(nil), spec...)
	return s.EditPolicyOnce(ctx, id, etag, spec, a, func(Policy) (json.RawMessage, error) { return spec, nil })
}

// EditPolicyOnce derives a draft from the locked current policy only on the
// first successful execution. Bind command to client input, not generated IDs
// or expiry timestamps. The callback must perform no external I/O.
func (s *Store) EditPolicyOnce(ctx context.Context, id, etag string, commandInput json.RawMessage, a Audit, edit func(Policy) (json.RawMessage, error)) (Policy, error) {
	return s.editPolicyOnce(ctx, id, etag, commandInput, a, edit, false, nil)
}

// EditPolicyAndReplayOnce atomically saves a derived draft, replay operation,
// both audits and the idempotent response. A committed draft cannot lose its replay
// across control-plane crashes. The runner later claims the durable operation.
func (s *Store) EditPolicyAndReplayOnce(ctx context.Context, id, etag string, commandInput json.RawMessage, a Audit, edit func(Policy) (json.RawMessage, error)) (Policy, error) {
	return s.editPolicyOnce(ctx, id, etag, commandInput, a, edit, true, nil)
}

func (s *Store) editPolicyOnce(ctx context.Context, id, etag string, commandInput json.RawMessage, a Audit, edit func(Policy) (json.RawMessage, error), queueReplay bool, prepare func(pgx.Tx) error) (Policy, error) {

	if id == "" || etag == "" || a.Subject == "" || a.RequestID == "" || len(a.RequestID) > 128 || len(commandInput) > 256*1024 || !json.Valid(commandInput) || edit == nil {
		return Policy{}, fmt.Errorf("store: invalid idempotent policy edit")
	}
	digest, err := policyEditFingerprint(id, etag, commandInput, a, queueReplay)
	if err != nil {
		return Policy{}, err
	}
	var result Policy
	err = s.inTx(ctx, func(tx pgx.Tx) error {
		// Lock order: request, then policy. Hash collisions only serialize writes;
		// the table's tuple key and full fingerprint still determine identity.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 713))`, a.Subject+"/"+a.RequestID); err != nil {
			return err
		}
		var fingerprint, response []byte
		err := tx.QueryRow(ctx, `SELECT fingerprint,response FROM policy_edit_requests WHERE subject=$1 AND request_id=$2`, a.Subject, a.RequestID).Scan(&fingerprint, &response)
		if err == nil {
			if !bytes.Equal(fingerprint, digest[:]) {
				return ErrRequestReused
			}
			if err := json.Unmarshal(response, &result); err != nil {
				return fmt.Errorf("decode policy edit reply: %w", err)
			}
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		before, err := scanPolicy(tx.QueryRow(ctx, `SELECT `+policyCols+policyFrom+` WHERE p.id=$1 FOR UPDATE OF p`, id))
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("read policy for edit: %w", err)
		}
		if before.Etag != etag {
			return ErrEtagMismatch
		}
		if prepare != nil {
			if err := prepare(tx); err != nil {
				return err
			}
		}
		spec, err := edit(before)
		if err != nil {
			return fmt.Errorf("derive policy draft: %w", err)
		}
		if len(spec) > 256*1024 || !json.Valid(spec) {
			return fmt.Errorf("invalid derived policy spec")
		}
		next, err := newEtag()
		if err != nil {
			return err
		}
		result, err = updatePolicyTx(ctx, tx, id, etag, spec, next, a)
		if err != nil {
			return err
		}
		if queueReplay {
			replayAudit := a
			replayAudit.Action, replayAudit.Resource = "policies.replay", "policies/"+id
			if _, err := createReplayOperationTx(ctx, tx, id, result.CurrentVersion, replayAudit); err != nil {
				return err
			}
		}
		result.CreatedAt = result.CreatedAt.UTC()
		result.UpdatedAt = result.UpdatedAt.UTC()
		response, err = json.Marshal(result)
		if err != nil {
			return fmt.Errorf("encode policy edit reply: %w", err)
		}
		_, err = tx.Exec(ctx, `INSERT INTO policy_edit_requests(subject,request_id,fingerprint,response) VALUES($1,$2,$3,$4)`, a.Subject, a.RequestID, digest[:], response)
		return err
	})
	if err != nil {
		return Policy{}, fmt.Errorf("store: idempotent policy edit: %w", err)
	}
	return result, nil
}

func policyEditFingerprint(id, etag string, input json.RawMessage, a Audit, queueReplay bool) ([32]byte, error) {
	command, err := json.Marshal(struct {
		ID          string
		Etag        string
		Spec        json.RawMessage
		Action      string
		Resource    string
		QueueReplay bool `json:"QueueReplay,omitempty"`
	}{id, etag, input, a.Action, a.Resource, queueReplay})
	if err != nil {
		return [32]byte{}, fmt.Errorf("store: encode policy edit: %w", err)
	}
	return sha256.Sum256(command), nil
}

// GetPolicyReplayEditResult reads a committed idempotent reply before looking up
// an event that may have expired from retention. Authorization belongs to the
// caller. The saved policy ID plus the full original command bind the response;
// another subject or changed content cannot retrieve it. ErrNotFound means the
// caller must execute EditPolicyAndReplayOnce, which serializes concurrent misses.
func (s *Store) GetPolicyReplayEditResult(ctx context.Context, etag string, input json.RawMessage, a Audit) (Policy, error) {
	if etag == "" || a.Subject == "" || a.RequestID == "" || len(a.RequestID) > 128 || len(input) > 256*1024 || !json.Valid(input) {
		return Policy{}, fmt.Errorf("store: invalid policy edit lookup")
	}
	var fingerprint, response []byte
	err := s.pool.QueryRow(ctx, `SELECT fingerprint,response FROM policy_edit_requests WHERE subject=$1 AND request_id=$2`, a.Subject, a.RequestID).Scan(&fingerprint, &response)
	if errors.Is(err, pgx.ErrNoRows) {
		return Policy{}, ErrNotFound
	}
	if err != nil {
		return Policy{}, fmt.Errorf("store: policy edit lookup: %w", err)
	}
	var p Policy
	if err := json.Unmarshal(response, &p); err != nil {
		return Policy{}, fmt.Errorf("store: policy reply: %w", err)
	}
	digest, err := policyEditFingerprint(p.ID, etag, input, a, true)
	if err != nil {
		return Policy{}, err
	}
	if !bytes.Equal(fingerprint, digest[:]) {
		return Policy{}, ErrRequestReused
	}
	return p, nil
}

// EditGeoPolicyAndReplayOnce allocates an ID under the same global reservation
// lock used by every policy-version insert. Rollback returns the unused ID.
func (s *Store) EditGeoPolicyAndReplayOnce(ctx context.Context, id, etag string, input json.RawMessage, a Audit, edit func(Policy, uint32) (json.RawMessage, error)) (Policy, error) {
	var ruleID uint32
	prepare := func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(741003)`); err != nil {
			return err
		}
		err := tx.QueryRow(ctx, `SELECT n FROM generate_series(190000,199999) n WHERE NOT EXISTS(SELECT 1 FROM policy_geo_rule_ids g WHERE g.rule_id=n) ORDER BY n LIMIT 1`).Scan(&ruleID)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("investigation: geo rule ID quota reached")
		}
		return err
	}
	return s.editPolicyOnce(ctx, id, etag, input, a, func(p Policy) (json.RawMessage, error) { return edit(p, ruleID) }, true, prepare)
}
