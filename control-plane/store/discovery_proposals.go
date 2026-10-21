package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/strata/strata/control-plane/apidiscovery"
	"time"
)

type DiscoveryProposal struct {
	PolicyID      string                   `json:"policy_id"`
	PolicyEtag    string                   `json:"policy_etag"`
	PolicyVersion int                      `json:"policy_version"`
	Draftable     bool                     `json:"draftable"`
	Changes       []apidiscovery.Change    `json:"changes"`
	ID            string                   `json:"id"`
	ApplicationID string                   `json:"application_id"`
	EnvironmentID string                   `json:"environment_id"`
	ScopeEtag     string                   `json:"-"`
	RouteID       string                   `json:"route_id"`
	BaseDigest    string                   `json:"base_digest"`
	Operations    []apidiscovery.Operation `json:"operations"`
	Digest        string                   `json:"digest"`
	Evidence      DiscoveredEndpoint       `json:"evidence"`
	Etag          string                   `json:"etag"`
	Owner         string                   `json:"owner"`
	CreatedAt     time.Time                `json:"created_at"`
	ExpiresAt     time.Time                `json:"expires_at"`
	DraftPolicyID string                   `json:"draft_policy_id"`
	DraftVersion  int                      `json:"draft_version"`
	ReviewState   string                   `json:"review_state"`
}

const discoveryProposalCols = `id::text,application_id,environment_id,scope_etag,route_id,base_digest,operations,digest,evidence,changes,etag,created_subject,created_at,expires_at,coalesce(draft_policy_id,''),coalesce(draft_version,0)`

func scanDiscoveryProposal(row pgx.Row) (DiscoveryProposal, error) {
	var v DiscoveryProposal
	var ops, evidence, changes []byte
	err := row.Scan(&v.ID, &v.ApplicationID, &v.EnvironmentID, &v.ScopeEtag, &v.RouteID, &v.BaseDigest, &ops, &v.Digest, &evidence, &changes, &v.Etag, &v.Owner, &v.CreatedAt, &v.ExpiresAt, &v.DraftPolicyID, &v.DraftVersion)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	if err == nil {
		err = json.Unmarshal(ops, &v.Operations)
	}
	if err == nil {
		err = json.Unmarshal(evidence, &v.Evidence)
	}
	if err == nil {
		err = json.Unmarshal(changes, &v.Changes)
	}
	return v, err
}
func (s *Store) CreateDiscoveryProposal(ctx context.Context, app, env, scope, endpoint, base string, a Audit) (DiscoveryProposal, error) {
	var out DiscoveryProposal
	if len(endpoint) != 64 || len(base) != 64 {
		return out, fmt.Errorf("discovery: invalid proposal input")
	}
	err := s.investigationOnce(ctx, struct{ App, Env, Scope, Endpoint, Base string }{app, env, scope, endpoint, base}, a, func(tx pgx.Tx) (any, error) {
		for _, lock := range []int{744001, 744002} {
			if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, lock); err != nil {
				return nil, err
			}
		}
		doc, err := scanDiscoveryDocument(tx.QueryRow(ctx, `SELECT `+discoveryDocCols+` FROM discovery_documents d WHERE d.application_id=$1 AND d.environment_id=$2 AND d.scope_etag=$3 AND EXISTS(SELECT 1 FROM applications a WHERE a.id=d.application_id AND a.etag=d.scope_etag) FOR UPDATE OF d`, app, env, scope))
		if err != nil {
			return nil, err
		}
		if doc.Digest != base {
			return nil, ErrEtagMismatch
		}
		endpoints, err := discoveredEndpoints(ctx, tx, app, env, scope, time.Now().UTC())
		if err != nil {
			return nil, err
		}
		var found *DiscoveredEndpoint
		for _, v := range endpoints {
			if v.Key == endpoint {
				copy := v
				found = &copy
				break
			}
		}
		if found == nil || !found.Eligible {
			return nil, fmt.Errorf("discovery: insufficient independent successful samples")
		}
		var total, own int
		if err = tx.QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE application_id=$1 AND environment_id=$2) FROM discovery_proposals`, app, env).Scan(&total, &own); err != nil {
			return nil, err
		}
		if total >= 1000 || own >= 20 {
			return nil, fmt.Errorf("discovery: proposal quota")
		}
		operations, err := apidiscovery.Propose(doc.Operations, found.Path, found.Method, found.ContentTypes, found.ObservedMaxBodyBytes)
		if err != nil {
			return nil, err
		}
		raw, err := json.Marshal(operations)
		if err != nil {
			return nil, err
		}
		evidence, err := json.Marshal(found)
		if err != nil {
			return nil, err
		}
		changes, err := json.Marshal(apidiscovery.Diff(doc.Operations, operations))
		if err != nil {
			return nil, err
		}
		return scanDiscoveryProposal(tx.QueryRow(ctx, `INSERT INTO discovery_proposals(application_id,environment_id,scope_etag,route_id,base_digest,operations,digest,evidence,changes,created_subject) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING `+discoveryProposalCols, app, env, scope, found.RouteID, base, raw, apidiscovery.Digest(operations), evidence, changes, a.Subject))
	}, &out)
	return out, err
}
func (s *Store) DiscoveryProposals(ctx context.Context, app, env, scope string, now time.Time) ([]DiscoveryProposal, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+discoveryProposalCols+` FROM discovery_proposals WHERE application_id=$1 AND environment_id=$2 AND scope_etag=$3 AND expires_at>$4 ORDER BY created_at DESC LIMIT 20`, app, env, scope, now)
	if err != nil {
		return nil, err
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (DiscoveryProposal, error) { return scanDiscoveryProposal(r) })
	if err != nil {
		return nil, err
	}
	for i, v := range out {
		out[i].ReviewState = "PROPOSED"
		if v.DraftVersion > 0 {
			p, err := s.GetPolicyVersion(ctx, v.DraftPolicyID, v.DraftVersion)
			if err != nil {
				return nil, err
			}
			out[i].ReviewState = p.State
		}
	}
	return out, nil
}

// DraftDiscoveryProposal binds the immutable document hash into an ordinary
// policy revision and replay in one transaction. The metadata has no runtime
// enforcement meaning; the current bundle format is unchanged.
func (s *Store) DraftDiscoveryProposal(ctx context.Context, id, proposalEtag, policyID, policyEtag, scope string, a Audit) (Policy, error) {
	input, _ := json.Marshal(struct{ ProposalID, ProposalEtag, Scope string }{id, proposalEtag, scope})
	var proposal DiscoveryProposal
	prepare := func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(744002)`); err != nil {
			return err
		}
		var err error
		proposal, err = scanDiscoveryProposal(tx.QueryRow(ctx, `SELECT `+discoveryProposalCols+` FROM discovery_proposals WHERE id::text=$1 AND etag=$2 AND scope_etag=$3 AND draft_version IS NULL AND expires_at>now() FOR UPDATE`, id, proposalEtag, scope))
		if errors.Is(err, ErrNotFound) {
			return ErrEtagMismatch
		}
		if err != nil {
			return err
		}
		var valid bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM applications a JOIN discovery_documents d ON d.application_id=a.id JOIN application_routes r ON r.application_id=a.id AND r.environment_id=d.environment_id WHERE a.id=$1 AND a.etag=$2 AND d.scope_etag=$2 AND d.environment_id=$3 AND d.digest=$4 AND r.id=$5 AND r.policy_id=$6)`, proposal.ApplicationID, scope, proposal.EnvironmentID, proposal.BaseDigest, proposal.RouteID, policyID).Scan(&valid); err != nil {
			return err
		}
		if !valid {
			return ErrEtagMismatch
		}
		_, err = tx.Exec(ctx, `UPDATE discovery_proposals SET draft_policy_id=$2,draft_version=(SELECT current_version+1 FROM policies WHERE id=$2),etag=gen_random_uuid()::text WHERE id::text=$1`, id, policyID)
		return err
	}
	return s.editPolicyOnce(ctx, policyID, policyEtag, input, a, func(before Policy) (json.RawMessage, error) {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(before.Spec, &fields); err != nil {
			return nil, err
		}
		ref, err := json.Marshal(map[string]any{"proposal_id": id, "document_sha256": proposal.Digest, "mode": "documentation_only"})
		if err != nil {
			return nil, err
		}
		fields["api_discovery"] = ref
		return json.Marshal(fields)
	}, true, prepare)
}
