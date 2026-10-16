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

	if id == "" || etag == "" || a.Subject == "" || a.RequestID == "" || len(a.RequestID) > 128 || len(commandInput) > 256*1024 || !json.Valid(commandInput) || edit == nil {
		return Policy{}, fmt.Errorf("store: invalid idempotent policy edit")
	}
	command, err := json.Marshal(struct {
		ID       string
		Etag     string
		Spec     json.RawMessage
		Action   string
		Resource string
	}{id, etag, commandInput, a.Action, a.Resource})
	if err != nil {
		return Policy{}, fmt.Errorf("store: encode policy edit: %w", err)
	}
	digest := sha256.Sum256(command)
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
