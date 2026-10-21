package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

type ExceptionOrigin struct {
	Owner     string    `json:"owner"`
	CreatedAt time.Time `json:"created_at"`
}

// Origins remain tied to the first saved version containing the exception ID.
func (s *Store) ExceptionOrigins(ctx context.Context, policy string, ids []string) (map[string]ExceptionOrigin, error) {
	if len(ids) > 128 {
		return nil, fmt.Errorf("exceptions: origin page exceeds 128")
	}
	rows, err := s.pool.Query(ctx, `SELECT DISTINCT ON (e->>'id') e->>'id',v.created_subject,v.created_at FROM policy_versions v CROSS JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(v.spec->'exceptions')='array' THEN v.spec->'exceptions' ELSE '[]'::jsonb END) e WHERE v.policy_id=$1 AND e->>'id'=ANY($2) ORDER BY e->>'id',v.version`, policy, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]ExceptionOrigin{}
	for rows.Next() {
		var id string
		var v ExceptionOrigin
		if err := rows.Scan(&id, &v.Owner, &v.CreatedAt); err != nil {
			return nil, err
		}
		out[id] = v
	}
	return out, rows.Err()
}
func (s *Store) ActivePolicyNodes(ctx context.Context, policy, group string) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM nodes n JOIN bundles b ON b.version=n.bundle_version WHERE n.group_id=$1 AND n.revoked_at IS NULL AND n.bundle_state='ACTIVE' AND b.contents ? $2`, group, policy).Scan(&n)
	return n, err
}
func (s *Store) GroupRuleDisabled(ctx context.Context, group string, rule uint32) (bool, error) {
	var disabled bool
	err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM disabled_rules WHERE group_id=$1 AND rule_id=$2)`, group, int64(rule)).Scan(&disabled)
	return disabled, err
}

// PolicyReadStates returns current and latest approved state without widening
// access. The caller must authorize this policy through its selected application.
func (s *Store) PolicyReadStates(ctx context.Context, id string) (Policy, PolicyVersion, error) {
	p, err := s.GetPolicy(ctx, id)
	if err != nil {
		return p, PolicyVersion{}, err
	}
	version := p.CurrentVersion
	if p.ApprovedVersion > 0 {
		version = p.ApprovedVersion
	}
	approved, err := s.GetPolicyVersion(ctx, id, version)
	return p, approved, err
}

// ExpiredExceptionCandidates pages policies whose latest approved revision has
// expired entries. Pending user drafts are detected again before any auto edit.
func (s *Store) ExpiredExceptionCandidates(ctx context.Context, after string, now time.Time) ([]Policy, error) {
	rows, err := s.pool.Query(ctx, `SELECT p.id FROM policies p JOIN LATERAL(SELECT spec FROM policy_versions WHERE policy_id=p.id AND state IN ('APPROVED','DEPLOYED') ORDER BY version DESC LIMIT 1) v ON true WHERE p.id>$1 AND EXISTS(SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(v.spec->'exceptions')='array' THEN v.spec->'exceptions' ELSE '[]'::jsonb END) e WHERE CASE WHEN e->>'expires_unix_ms' ~ '^[0-9]{1,19}$' THEN (e->>'expires_unix_ms')::numeric END<=$2) ORDER BY p.id LIMIT 100`, after, now.UnixMilli())
	if err != nil {
		return nil, err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}
	out := []Policy{}
	for _, id := range ids {
		p, err := s.GetPolicy(ctx, id)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

type ExceptionRoute struct {
	PolicyID string
	Host     string
	Prefix   string
}
type ExceptionRow struct {
	PolicyID        string
	PolicyName      string
	Version         int
	Etag            string
	State           string
	DecidedBy       string
	ReplayID        string
	Raw             []byte
	CurrentContains bool
	ActiveNodes     int
	Cursor          string
}

// Page current, latest approved and node-active revisions in SQL. Never load all
// policy histories/exception payloads into the API process just to pick a page.
func (s *Store) ExceptionRows(ctx context.Context, ids []string, routes []ExceptionRoute, group, after string) ([]ExceptionRow, error) {
	if len(ids) > 128 || len(routes) > 128 {
		return nil, fmt.Errorf("exceptions: route scope too large")
	}
	if len(ids) == 0 {
		return []ExceptionRow{}, nil
	}
	raw, err := json.Marshal(routes)
	if err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `WITH candidates AS (
 SELECT p.id,p.name,p.etag,v.version,v.state,coalesce(v.decided_by,''),coalesce(v.approved_replay_id,''),e.value,
 coalesce((SELECT cv.spec->'exceptions' @> jsonb_build_array(jsonb_build_object('id',e.value->>'id')) FROM policy_versions cv WHERE cv.policy_id=p.id AND cv.version=p.current_version),false) current_contains,
 (SELECT count(*) FROM nodes n JOIN bundles b ON b.version=n.bundle_version WHERE n.group_id=$3 AND n.revoked_at IS NULL AND n.bundle_state='ACTIVE' AND b.contents->>p.id=v.version::text) active_nodes,
 p.id||'/'||lpad(v.version::text,10,'0')||'/'||(e.value->>'id') cursor
 FROM policies p JOIN policy_versions v ON v.policy_id=p.id
 CROSS JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(v.spec->'exceptions')='array' THEN v.spec->'exceptions' ELSE '[]'::jsonb END) e
 WHERE p.id=ANY($1) AND (v.version=p.current_version OR v.version=(SELECT max(av.version) FROM policy_versions av WHERE av.policy_id=p.id AND av.state IN('APPROVED','DEPLOYED')) OR EXISTS(SELECT 1 FROM nodes n JOIN bundles b ON b.version=n.bundle_version WHERE n.group_id=$3 AND n.revoked_at IS NULL AND n.bundle_state='ACTIVE' AND b.contents->>p.id=v.version::text))
 AND EXISTS(SELECT 1 FROM jsonb_array_elements($2::jsonb) r WHERE r->>'PolicyID'=p.id AND lower(r->>'Host')=lower(e.value->>'host') AND starts_with(e.value->>'path',r->>'Prefix'))
 ) SELECT * FROM candidates WHERE cursor>$4 ORDER BY cursor LIMIT 201`, ids, raw, group, after)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (ExceptionRow, error) {
		var v ExceptionRow
		err := r.Scan(&v.PolicyID, &v.PolicyName, &v.Etag, &v.Version, &v.State, &v.DecidedBy, &v.ReplayID, &v.Raw, &v.CurrentContains, &v.ActiveNodes, &v.Cursor)
		return v, err
	})
}
