package ingest

import (
	"context"
	"strings"

	"github.com/strata/strata/control-plane/auth"
)

func scopedEvents(ctx context.Context) bool {
	p := auth.FromContext(ctx)
	return p != nil && p.Access != nil
}
func eventAllowed(ctx context.Context, e Event) bool {
	p := auth.FromContext(ctx)
	if p == nil || p.Access == nil {
		return true
	}
	for _, r := range p.Access.Events {
		if r.Policy != e.PolicyID || r.Host != strings.ToLower(e.HTTPHost) || !strings.HasPrefix(e.HTTPPath, r.Prefix) {
			continue
		}
		for _, n := range r.Nodes {
			if e.NodeID == n {
				return true
			}
		}
	}
	return false
}
func eventScopeSQL(ctx context.Context) (string, []any) {
	p := auth.FromContext(ctx)
	if p == nil || p.Access == nil {
		return "1", nil
	}
	terms := []string{}
	args := []any{}
	for _, r := range p.Access.Events {
		if len(r.Nodes) == 0 {
			continue
		}
		terms = append(terms, "(policy_id = ? AND lowerUTF8(http_host) = ? AND startsWith(http_path, ?) AND has(?, node_id))")
		args = append(args, r.Policy, r.Host, r.Prefix, r.Nodes)
	}
	if len(terms) == 0 {
		return "0", nil
	}
	return "(" + strings.Join(terms, " OR ") + ")", args
}
func appendEventScope(ctx context.Context, where string, args []any) (string, []any) {
	clause, scopeArgs := eventScopeSQL(ctx)
	return "(" + where + ") AND " + clause, append(args, scopeArgs...)
}
func (s *ClickHouseStore) scopedGeoTable(ctx context.Context, table string) (string, []any) {
	if !scopedEvents(ctx) {
		return table, nil
	}
	clause, args := eventScopeSQL(ctx)
	if table == GeoGridTable {
		return "(" + s.geoGridSelect("WHERE "+clause) + ")", args
	}
	return "(" + s.geoMinuteSelect("WHERE "+clause) + ")", args
}
