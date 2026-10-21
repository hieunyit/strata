package store

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/strata/strata/control-plane/auth"
)

func (s *Store) ApplicationBindings(ctx context.Context) ([]ApplicationBinding, error) {
	rows, err := s.pool.Query(ctx, "SELECT id,subject,role,application_id,environment_id FROM application_role_bindings ORDER BY id LIMIT 5000")
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (ApplicationBinding, error) {
		var b ApplicationBinding
		err := r.Scan(&b.ID, &b.Subject, &b.Role, &b.ApplicationID, &b.EnvironmentID)
		return b, err
	})
}

func (s *Store) AddApplicationBinding(ctx context.Context, b ApplicationBinding, audit Audit) (ApplicationBinding, error) {
	namespace, identity, _ := strings.Cut(b.Subject, ":")
	if (namespace != "local" && namespace != "oidc" && namespace != "sa") || identity == "" || len(b.Subject) > 512 || len(auth.ParseRoles([]string{b.Role})) != 1 {
		return b, errors.New("binding: invalid subject or role")
	}
	if b.ApplicationID == nil && b.EnvironmentID != nil {
		return b, errors.New("binding: environment requires application")
	}
	if b.ID != 0 || len(b.RequestID) > 128 {
		return b, errors.New("binding: invalid id or request_id")
	}
	command, err := json.Marshal(b)
	if err != nil {
		return b, err
	}
	digest := sha256.Sum256(command)
	err = s.inTx(ctx, func(tx pgx.Tx) error {
		if b.RequestID != "" {
			if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,33))", audit.Subject+"/"+b.RequestID); err != nil {
				return err
			}
			var prior, response []byte
			err := tx.QueryRow(ctx, "SELECT digest,response FROM application_write_requests WHERE subject=$1 AND request_id=$2 AND action='binding.create'", audit.Subject, b.RequestID).Scan(&prior, &response)
			if err == nil {
				if string(prior) != string(digest[:]) {
					return ErrApplicationConflict
				}
				return json.Unmarshal(response, &b)
			}
			if !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
		}
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,32))", b.Subject); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "INSERT INTO application_subjects(subject) VALUES($1) ON CONFLICT DO NOTHING", b.Subject); err != nil {
			return err
		}
		var n int
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM application_role_bindings WHERE subject=$1", b.Subject).Scan(&n); err != nil {
			return err
		}
		if n >= 128 {
			return errors.New("binding: too many bindings for subject")
		}
		err := tx.QueryRow(ctx, `INSERT INTO application_role_bindings(subject,role,application_id,environment_id,created_by) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING RETURNING id`, b.Subject, b.Role, b.ApplicationID, b.EnvironmentID, audit.Actor).Scan(&b.ID)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrExists
		}
		if err != nil {
			return err
		}
		audit.Resource = fmt.Sprintf("rolebindings/%d", b.ID)
		audit.After = b
		if err := writeAudit(ctx, tx, audit); err != nil {
			return err
		}
		if b.RequestID != "" {
			response, err := json.Marshal(b)
			if err != nil {
				return err
			}
			_, err = tx.Exec(ctx, "INSERT INTO application_write_requests(subject,request_id,action,digest,response) VALUES($1,$2,'binding.create',$3,$4)", audit.Subject, b.RequestID, digest[:], response)
			return err
		}
		return nil
	})
	return b, err
}

func (s *Store) DeleteApplicationBinding(ctx context.Context, id int64, audit Audit) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		var b ApplicationBinding
		err := tx.QueryRow(ctx, "DELETE FROM application_role_bindings WHERE id=$1 RETURNING id,subject,role,application_id,environment_id", id).Scan(&b.ID, &b.Subject, &b.Role, &b.ApplicationID, &b.EnvironmentID)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		audit.Resource = fmt.Sprintf("rolebindings/%d", id)
		audit.Before = b
		return writeAudit(ctx, tx, audit)
	})
}

// ResolveApplicationAccess resolves explicit bindings; no bindings preserves old RBAC.
func (s *Store) ResolveApplicationAccess(ctx context.Context, p *auth.Principal) (*auth.Principal, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	rows, err := tx.Query(ctx, "SELECT id,subject,role,application_id,environment_id FROM application_role_bindings WHERE subject=$1 ORDER BY id LIMIT 129", p.Subject)
	if err != nil {
		return nil, err
	}
	bs, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (ApplicationBinding, error) {
		var b ApplicationBinding
		err := r.Scan(&b.ID, &b.Subject, &b.Role, &b.ApplicationID, &b.EnvironmentID)
		return b, err
	})
	if err != nil {
		return nil, err
	}
	if len(bs) == 0 {
		var scoped bool
		if err := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM application_subjects WHERE subject=$1)", p.Subject).Scan(&scoped); err != nil {
			return nil, err
		}
		if scoped {
			p.Roles = nil
			p.Access = &auth.Access{Applications: map[string]bool{}, Resources: map[string]map[auth.Permission]bool{}}
		}
		return p, nil
	}
	if len(bs) > 128 {
		return nil, errors.New("access: excessive bindings")
	}
	roles := []string{}
	global := []string{}
	for _, b := range bs {
		roles = append(roles, b.Role)
		if b.ApplicationID == nil {
			global = append(global, b.Role)
		}
	}
	if len(global) > 0 {
		p.Roles = auth.ParseRoles(global)
		return p, nil
	}
	p.Roles = auth.ParseRoles(roles)
	access := &auth.Access{Applications: map[string]bool{}, Environments: map[string]bool{}, Resources: map[string]map[auth.Permission]bool{}}
	grant := func(resource string, perm auth.Permission) {
		if access.Resources[resource] == nil {
			access.Resources[resource] = map[auth.Permission]bool{}
		}
		access.Resources[resource][perm] = true
	}
	allowed := func(app, env string, perm auth.Permission) bool {
		for _, b := range bs {
			if b.ApplicationID != nil && *b.ApplicationID == app && (b.EnvironmentID == nil || *b.EnvironmentID == env) && auth.Role(b.Role).Allows(perm) {
				return true
			}
		}
		return false
	}
	for _, b := range bs {
		env := "*"
		if b.EnvironmentID != nil {
			env = *b.EnvironmentID
		}
		access.Environments[*b.ApplicationID+"/"+env] = true
		access.Applications[*b.ApplicationID] = true
		grant("applications/"+*b.ApplicationID, auth.PermApplicationsRead)
	}
	// All references are considered for shared-policy writes, including inaccessible apps.
	routes, err := tx.Query(ctx, `SELECT r.application_id,r.environment_id,r.policy_id,p.name,r.host,r.path_prefix,e.group_id FROM application_routes r JOIN policies p ON p.id=r.policy_id JOIN application_environments e ON (e.application_id,e.id)=(r.application_id,r.environment_id) ORDER BY r.application_id,r.id LIMIT 10001`)
	if err != nil {
		return nil, err
	}
	type ref struct{ app, env, policy, name, host, prefix, group string }
	refs, err := pgx.CollectRows(routes, func(row pgx.CollectableRow) (ref, error) {
		var r ref
		err := row.Scan(&r.app, &r.env, &r.policy, &r.name, &r.host, &r.prefix, &r.group)
		return r, err
	})
	if err != nil {
		return nil, err
	}
	if len(refs) > 10000 {
		return nil, errors.New("access: excessive route graph")
	}
	policies := map[string][]ref{}
	groups := map[string]bool{}
	for _, r := range refs {
		policies[r.policy] = append(policies[r.policy], r)
		if allowed(r.app, r.env, auth.PermNodesRead) {
			groups[r.group] = true
			grant("groups/"+r.group, auth.PermNodesRead)
		}
	}
	nodes, err := tx.Query(ctx, "SELECT id,group_id FROM nodes WHERE revoked_at IS NULL LIMIT 10001")
	if err != nil {
		return nil, err
	}
	groupNodes := map[string][]string{}
	nodeCount := 0
	for nodes.Next() {
		nodeCount++
		if nodeCount > 10000 {
			nodes.Close()
			return nil, errors.New("access: excessive node graph")
		}
		var id, g string
		if err := nodes.Scan(&id, &g); err != nil {
			nodes.Close()
			return nil, err
		}
		groupNodes[g] = append(groupNodes[g], id)
		if groups[g] {
			grant("nodes/"+id, auth.PermNodesRead)
		}
	}
	if err := nodes.Err(); err != nil {
		nodes.Close()
		return nil, err
	}
	nodes.Close()
	for id, uses := range policies {
		for _, perm := range []auth.Permission{auth.PermPoliciesRead, auth.PermPoliciesWrite, auth.PermPoliciesApprove, auth.PermPoliciesDeploy, auth.PermExceptionsWrite} {
			any, all := false, true
			for _, r := range uses {
				ok := allowed(r.app, r.env, perm)
				any = any || ok
				all = all && ok
			}
			if (perm == auth.PermPoliciesRead && any) || (perm != auth.PermPoliciesRead && all) {
				grant("policies/"+id, perm)
				for _, r := range uses {
					grant("eventpolicies/"+r.name, perm)
				}
			}
		}
	}
	for _, r := range refs {
		if allowed(r.app, r.env, auth.PermEventsRead) {
			sort.Strings(groupNodes[r.group])
			access.Events = append(access.Events, auth.EventScope{Policy: r.name, Host: r.host, Prefix: r.prefix, Sensitive: allowed(r.app, r.env, auth.PermEventsReadSensitive), Nodes: groupNodes[r.group]})
		}
	}
	// Indirect IDs are resolved on demand, avoiding an unbounded operation graph.
	access.Lookup = func(resource string, perm auth.Permission) bool {
		parts := strings.SplitN(resource, "/", 2)
		if len(parts) != 2 || parts[1] == "" {
			return false
		}
		var owner string
		var err error
		switch parts[0] {
		case "operations":
			err = s.pool.QueryRow(ctx, "SELECT policy_id FROM operations WHERE id=$1", parts[1]).Scan(&owner)
			return err == nil && access.Resources["policies/"+owner][perm]
		case "commands":
			err = s.pool.QueryRow(ctx, "SELECT node_id FROM node_commands WHERE id=$1", parts[1]).Scan(&owner)
			return err == nil && access.Resources["nodes/"+owner][perm]
		}
		return false
	}
	p.Access = access
	return p, nil
}

// ApplicationEventScope narrows even a global administrator's dashboard to one
// application's owned routes. Existing scoped access is intersected, never widened.
func (s *Store) ApplicationEventScope(ctx context.Context, id, environment string, p *auth.Principal) (context.Context, error) {
	if !p.CanResource("applications/"+id, auth.PermApplicationsRead) {
		return nil, ErrNotFound
	}
	a, err := s.GetApplication(ctx, id)
	if err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `SELECT p.name,r.host,r.path_prefix,n.id FROM application_routes r JOIN policies p ON p.id=r.policy_id JOIN application_environments e ON (e.application_id,e.id)=(r.application_id,r.environment_id) JOIN nodes n ON n.group_id=e.group_id AND n.revoked_at IS NULL WHERE r.application_id=$1 AND ($2='' OR r.environment_id=$2) ORDER BY r.id,n.id`, a.ID, environment)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	access := &auth.Access{Applications: map[string]bool{id: true}, Resources: map[string]map[auth.Permission]bool{}}
	byRoute := map[string]int{}
	for rows.Next() {
		var scope auth.EventScope
		var node string
		if err := rows.Scan(&scope.Policy, &scope.Host, &scope.Prefix, &node); err != nil {
			return nil, err
		}
		scope.Nodes = []string{node}
		scope.Sensitive = p.Can(auth.PermEventsReadSensitive)
		permitted := p.Access == nil
		if p.Access != nil {
			for _, old := range p.Access.Events {
				if old.Policy != scope.Policy || old.Host != scope.Host || old.Prefix != scope.Prefix {
					continue
				}
				for _, n := range old.Nodes {
					if n == node {
						permitted = true
					}
				}
			}
		}
		if permitted {
			key := scope.Policy + "\x00" + scope.Host + "\x00" + scope.Prefix
			if at, ok := byRoute[key]; ok {
				access.Events[at].Nodes = append(access.Events[at].Nodes, node)
			} else {
				byRoute[key] = len(access.Events)
				access.Events = append(access.Events, scope)
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	clone := *p
	clone.Access = access
	return auth.WithPrincipal(ctx, &clone), nil
}
