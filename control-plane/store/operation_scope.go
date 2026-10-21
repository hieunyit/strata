package store

import (
	"context"
	"github.com/jackc/pgx/v5"
	"github.com/strata/strata/control-plane/auth"
	"strconv"
	"time"
)

type OperationScope struct{ ApplicationID, EnvironmentID string }

func (s *Store) OperationScopes(ctx context.Context, after string) ([]OperationScope, error) {
	rows, err := s.pool.Query(ctx, `SELECT application_id,id FROM application_environments WHERE application_id||'/'||id>$1 ORDER BY application_id,id LIMIT 10`, after)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (OperationScope, error) {
		var v OperationScope
		err := r.Scan(&v.ApplicationID, &v.EnvironmentID)
		return v, err
	})
}

// OperationPrincipal describes an entire current environment. Readers must own
// that environment and every policy/node used by this aggregate.
func (s *Store) OperationPrincipal(ctx context.Context, a Application, env string) (*auth.Principal, error) {
	p := &auth.Principal{Subject: "system:operations", Roles: []auth.Role{auth.RoleAdmin}, Access: &auth.Access{Applications: map[string]bool{a.ID: true}, Environments: map[string]bool{a.ID + "/" + env: true}, Resources: map[string]map[auth.Permission]bool{}}}
	add := func(resource string, perm auth.Permission) {
		if p.Access.Resources[resource] == nil {
			p.Access.Resources[resource] = map[auth.Permission]bool{}
		}
		p.Access.Resources[resource][perm] = true
	}
	add("applications/"+a.ID, auth.PermApplicationsRead)
	group := ""
	for _, e := range a.Environments {
		if e.ID == env {
			group = e.GroupID
		}
	}
	rows, err := s.pool.Query(ctx, `SELECT id FROM nodes WHERE group_id=$1 AND revoked_at IS NULL ORDER BY id LIMIT 1001`, group)
	if err != nil {
		return nil, err
	}
	nodes, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}
	if len(nodes) > 1000 {
		return nil, auth.ErrScopeDenied
	}
	for _, n := range nodes {
		add("nodes/"+n, auth.PermNodesRead)
	}
	for _, r := range a.Routes {
		if r.EnvironmentID != env {
			continue
		}
		add("policies/"+r.PolicyID, auth.PermPoliciesRead)
		policy, err := s.GetPolicy(ctx, r.PolicyID)
		if err != nil {
			return nil, err
		}
		p.Access.Events = append(p.Access.Events, auth.EventScope{Policy: policy.Name, Host: r.Host, Prefix: r.PathPrefix, Nodes: nodes})
	}
	return p, nil
}

// Counter growth is unknown on first observation/reset or after a stale gap.
func (s *Store) OperationCounterGrowth(ctx context.Context, kind, node string, value uint64, at time.Time) (bool, bool, error) {
	var growth, known bool
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(743003)`); err != nil {
			return err
		}
		var old string
		var previous time.Time
		err := tx.QueryRow(ctx, `SELECT value::text,at FROM operation_counter_baselines WHERE kind=$1 AND node_id=$2`, kind, node).Scan(&old, &previous)
		if err != nil && err != pgx.ErrNoRows {
			return err
		}
		if err == nil {
			n, parseErr := strconv.ParseUint(old, 10, 64)
			if parseErr != nil {
				return parseErr
			}
			known = at.After(previous) && at.Sub(previous) <= 5*time.Minute && value >= n
			growth = at.After(previous) && at.Sub(previous) <= 5*time.Minute && value > n
			if !at.After(previous) {
				return nil
			}
		}
		_, err = tx.Exec(ctx, `INSERT INTO operation_counter_baselines(kind,node_id,value,at) VALUES($1,$2,$3::numeric,$4) ON CONFLICT(kind,node_id) DO UPDATE SET value=$3::numeric,at=$4`, kind, node, strconv.FormatUint(value, 10), at)
		return err
	})
	return growth, known, err
}
