package ruleinventory

import (
	"context"
	"encoding/json"
	"sort"
	"time"

	"github.com/strata/strata/agent/pkg/privacy"
	"github.com/strata/strata/control-plane/auth"
	"github.com/strata/strata/control-plane/policy"
	"github.com/strata/strata/control-plane/rulecat"
	"github.com/strata/strata/control-plane/store"
)

func Application(ctx context.Context, st *store.Store, app, env string) (store.Application, error) {
	p := auth.FromContext(ctx)
	if app == "" || env == "" || !p.CanResource("applications/"+app, auth.PermApplicationsRead) {
		return store.Application{}, store.ErrNotFound
	}
	if p.Access != nil && !p.Access.Environments[app+"/"+env] && !p.Access.Environments[app+"/*"] {
		return store.Application{}, store.ErrNotFound
	}
	a, err := st.GetApplication(ctx, app)
	if err != nil {
		return a, err
	}
	found := false
	for _, e := range a.Environments {
		if e.ID == env {
			found = true
		}
	}
	if !found {
		return a, store.ErrNotFound
	}
	return a, nil
}

type ExceptionItem struct {
	PolicyID      string                `json:"policy_id"`
	PolicyName    string                `json:"policy_name"`
	PolicyVersion int                   `json:"policy_version"`
	Etag          string                `json:"etag"`
	Exception     policy.Exception      `json:"exception"`
	Owner         store.ExceptionOrigin `json:"origin"`
	State         string                `json:"state"`
	DecidedBy     string                `json:"decided_by"`
	ReplayID      string                `json:"approved_replay_id"`
	Warnings      []string              `json:"warnings"`
	MatchSource   string                `json:"match_source"`
	UnusedStatus  string                `json:"unused_status"`
	Editable      bool                  `json:"editable"`
	ActiveNodes   int                   `json:"active_nodes"`
}
type ExceptionPage struct {
	Exceptions  []ExceptionItem              `json:"exceptions"`
	Next        string                       `json:"next_cursor"`
	Maintenance []store.ExceptionMaintenance `json:"maintenance"`
	At          time.Time                    `json:"at"`
}

func Exceptions(ctx context.Context, st *store.Store, catalog *rulecat.Catalog, app, env, after string, now time.Time) (ExceptionPage, error) {
	out := ExceptionPage{Exceptions: []ExceptionItem{}, Maintenance: []store.ExceptionMaintenance{}, At: now}
	a, err := Application(ctx, st, app, env)
	if err != nil {
		return out, err
	}
	p := auth.FromContext(ctx)
	policies := map[string]bool{}
	routes := []store.ExceptionRoute{}
	group := ""
	for _, e := range a.Environments {
		if e.ID == env {
			group = e.GroupID
		}
	}
	for _, r := range a.Routes {
		if r.EnvironmentID == env && p.CanResource("policies/"+r.PolicyID, auth.PermPoliciesRead) {
			policies[r.PolicyID] = true
			routes = append(routes, store.ExceptionRoute{PolicyID: r.PolicyID, Host: r.Host, Prefix: r.PathPrefix})
		}
	}
	ids := []string{}
	for id := range policies {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	rows, err := st.ExceptionRows(ctx, ids, routes, group, after)
	if err != nil {
		return out, err
	}
	if len(rows) > 200 {
		out.Next = rows[199].Cursor
		rows = rows[:200]
	}
	byPolicy := map[string]map[string]bool{}
	for _, row := range rows {
		var e policy.Exception
		if err := json.Unmarshal(row.Raw, &e); err != nil {
			return out, err
		}
		if err := e.Validate(); err != nil {
			return out, err
		}
		warnings := []string{}
		if e.Path == "/" {
			warnings = append(warnings, "too_broad")
		}
		if e.ExpiresUnixMS <= now.UnixMilli() {
			warnings = append(warnings, "expired")
		} else if e.ExpiresUnixMS <= now.Add(72*time.Hour).UnixMilli() {
			warnings = append(warnings, "expiring")
		}
		if catalog != nil && len(catalog.For([]uint32{e.RuleID})) == 0 {
			warnings = append(warnings, "not_in_configured_catalog")
		}
		e.Reason = (*privacy.Filter)(nil).Text(e.Reason)
		if !p.Can(auth.PermEventsReadSensitive) {
			e.Reason = ""
		}
		out.Exceptions = append(out.Exceptions, ExceptionItem{PolicyID: row.PolicyID, PolicyName: row.PolicyName, PolicyVersion: row.Version, Etag: row.Etag, Exception: e, State: row.State, DecidedBy: row.DecidedBy, ReplayID: row.ReplayID, Warnings: warnings, MatchSource: "not_collected", UnusedStatus: "unknown", Editable: row.CurrentContains && p.CanResource("policies/"+row.PolicyID, auth.PermExceptionsWrite), ActiveNodes: row.ActiveNodes})
		if byPolicy[row.PolicyID] == nil {
			byPolicy[row.PolicyID] = map[string]bool{}
		}
		byPolicy[row.PolicyID][e.ID] = true
	}
	origins := map[string]map[string]store.ExceptionOrigin{}
	for id, keys := range byPolicy {
		origins[id] = map[string]store.ExceptionOrigin{}
		list := []string{}
		for key := range keys {
			list = append(list, key)
		}
		sort.Strings(list)
		for start := 0; start < len(list); start += 128 {
			end := min(start+128, len(list))
			value, err := st.ExceptionOrigins(ctx, id, list[start:end])
			if err != nil {
				return out, err
			}
			for key, v := range value {
				origins[id][key] = v
			}
		}
	}
	for i, v := range out.Exceptions {
		out.Exceptions[i].Owner = origins[v.PolicyID][v.Exception.ID]
	}
	for _, id := range ids {
		if !p.CanResource("policies/"+id, auth.PermExceptionsWrite) && !p.CanResource("policies/"+id, auth.PermPoliciesApprove) {
			continue
		}
		task, err := st.ExceptionMaintenance(ctx, id)
		if err != nil {
			return out, err
		}
		if len(task) > 0 {
			out.Maintenance = append(out.Maintenance, task[0])
		}
	}
	return out, nil
}

type RuleUse struct {
	ApplicationID     string `json:"application_id"`
	EnvironmentID     string `json:"environment_id"`
	PolicyID          string `json:"policy_id"`
	PolicyName        string `json:"policy_name"`
	PolicyMode        string `json:"policy_mode"`
	PolicyVersion     int    `json:"policy_version"`
	State             string `json:"state"`
	Disabled          bool   `json:"disabled"`
	ActivePolicyNodes int    `json:"active_policy_nodes"`
	Source            string `json:"source"`
}

func Usage(ctx context.Context, st *store.Store, rule rulecat.Entry, app, env string) ([]RuleUse, error) {
	a, err := Application(ctx, st, app, env)
	if err != nil {
		return nil, err
	}
	group := ""
	for _, e := range a.Environments {
		if e.ID == env {
			group = e.GroupID
		}
	}
	seen := map[string]bool{}
	out := []RuleUse{}
	for _, route := range a.Routes {
		if route.EnvironmentID != env || seen[route.PolicyID] || !auth.FromContext(ctx).CanResource("policies/"+route.PolicyID, auth.PermPoliciesRead) {
			continue
		}
		seen[route.PolicyID] = true
		current, state, err := st.PolicyReadStates(ctx, route.PolicyID)
		if err != nil {
			return nil, err
		}
		spec, err := policy.Parse(state.Spec)
		if err != nil {
			return nil, err
		}
		_, shadow := spec.ParanoiaLevels()
		if rule.Paranoia > shadow {
			continue
		}
		if rule.Plugin != "" {
			found := false
			for _, plugin := range spec.CRSPlugins {
				if plugin == rule.Plugin {
					found = true
				}
			}
			if !found {
				continue
			}
		}
		disabled, err := st.GroupRuleDisabled(ctx, group, rule.ID)
		if err != nil {
			return nil, err
		}
		nodes, err := st.ActivePolicyNodes(ctx, route.PolicyID, group)
		if err != nil {
			return nil, err
		}
		out = append(out, RuleUse{app, env, route.PolicyID, current.Name, spec.Mode, state.Version, state.State, disabled, nodes, "configured_catalog_and_policy_bindings"})
	}
	return out, nil
}
