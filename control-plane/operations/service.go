// Package operations builds bounded, payload-free operational incidents/reports.
package operations

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/strata/strata/control-plane/auth"
	"github.com/strata/strata/control-plane/health"
	"github.com/strata/strata/control-plane/ingest"
	"github.com/strata/strata/control-plane/ruleinventory"
	"github.com/strata/strata/control-plane/store"
	"log"
	"sort"
	"time"
)

type Service struct {
	Store    *store.Store
	Health   *health.Service
	Events   ingest.EventStore
	Outbound bool
	Now      func() time.Time
	cursor   string
}
type Signal struct {
	Kind     string `json:"kind"`
	State    string `json:"state"`
	Affected int    `json:"affected"`
}
type Summary struct {
	Source      string    `json:"source"`
	ObservedAt  time.Time `json:"observed_at"`
	Signals     []Signal  `json:"signals"`
	Events      *uint64   `json:"security_events"`
	Blocked     *uint64   `json:"blocked_security_events"`
	EventStatus string    `json:"event_status"`
	Truncated   bool      `json:"truncated"`
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}
func (s *Service) Run(ctx context.Context) {
	timer := time.NewTicker(time.Minute)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			bounded, cancel := context.WithTimeout(ctx, 55*time.Second)
			err := s.Once(bounded)
			cancel()
			if err != nil && ctx.Err() == nil {
				log.Print("[WARN] operations scan incomplete")
			}
		}
	}
}

var causes = map[string]bool{"postgres": true, "lease": true, "clickhouse": true, "artifact_disk": true, "ingest_queue": true, "ingest_lag": true, "invalid_events": true, "not_inspected": true, "failed_operations": true, "heartbeat": true, "certificate": true, "bundle_drift": true, "spool_bytes": true, "spool_dropped": true, "fail_open": true, "dropped_events": true}

func Signals(v health.Snapshot) []Signal {
	m := map[string]Signal{}
	rank := map[string]int{"healthy": 0, "unknown": 1, "stale": 2, "degraded": 3, "unavailable": 4}
	add := func(c health.Check) {
		if !causes[c.ID] {
			return
		}
		old, ok := m[c.ID]
		if !ok {
			old = Signal{Kind: c.ID, State: c.State}
		}
		if rank[c.State] > rank[old.State] {
			old.State = c.State
		}
		if c.State == "degraded" || c.State == "unavailable" {
			old.Affected++
		}
		m[c.ID] = old
	}
	for _, c := range v.Checks {
		add(c)
	}
	for _, n := range v.Nodes {
		for _, c := range n.Checks {
			add(c)
		}
	}
	out := []Signal{}
	for _, v := range m {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Kind < out[j].Kind })
	return out
}
func (s *Service) summary(ctx context.Context, p *auth.Principal, from, to time.Time) (Summary, error) {
	v := s.Health.Collect(ctx, p)
	out := Summary{Source: "operational_health_and_security_events", ObservedAt: s.now(), Signals: Signals(v), EventStatus: "unavailable", Truncated: v.Truncated}
	// Cumulative counters must grow between fresh observations to alert. Their
	// lifetime totals are not an ongoing incident after a single historical drop.
	if p == nil {
		for ni := range v.Nodes {
			n := &v.Nodes[ni]
			for ci := range n.Checks {
				c := &n.Checks[ci]
				if c.ID != "fail_open" && c.ID != "dropped_events" && c.ID != "spool_dropped" {
					continue
				}
				if c.State != "healthy" && c.State != "degraded" {
					continue
				}
				if c.Value == nil || c.ObservedAt == nil {
					continue
				}
				value, err := parseCounter(*c.Value)
				if err != nil {
					return out, err
				}
				growth, known, err := s.Store.OperationCounterGrowth(ctx, c.ID, n.ID, value, *c.ObservedAt)
				if err != nil {
					return out, err
				}
				c.State = "unknown"
				if known {
					c.State = "healthy"
				}
				if growth {
					c.State = "degraded"
				}
			}
		}
		out.Signals = Signals(v)
		ok, at, err := s.Store.BackupObservation(ctx)
		state := "unknown"
		if err == nil {
			state = "healthy"
			if !ok {
				state = "degraded"
			} else if s.now().Sub(at) > 8*24*time.Hour {
				state = "stale"
			}
		} else if !errors.Is(err, store.ErrNotFound) {
			return out, err
		}
		out.Signals = append(out.Signals, Signal{Kind: "backup", State: state, Affected: boolInt(state == "degraded")})
	}
	if s.Events != nil && p != nil {
		ctx = auth.WithPrincipal(ctx, p)
		result, err := s.Events.SearchEvents(ctx, ingest.SearchFilter{From: from, To: to, Limit: 1})
		if err == nil && result != nil {
			out.Events = &result.Total
			blocked, err := s.Events.SearchEvents(ctx, ingest.SearchFilter{From: from, To: to, Action: "block", Limit: 1})
			if err == nil && blocked != nil {
				out.Blocked = &blocked.Total
				out.EventStatus = "available"
			}
		}
	}
	return out, nil
}
func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
func (s *Service) Once(ctx context.Context) error {
	now := s.now()
	if err := s.Store.RetainOperations(ctx, now); err != nil {
		return err
	}
	global, err := s.summary(ctx, nil, now.Add(-24*time.Hour), now)
	if err != nil {
		return err
	}
	if err = s.observe(ctx, "", "", "", global); err != nil {
		return err
	}
	scopes, err := s.Store.OperationScopes(ctx, s.cursor)
	if err != nil {
		return err
	}
	for _, scope := range scopes {
		a, err := s.Store.GetApplication(ctx, scope.ApplicationID)
		if err != nil {
			return err
		}
		p, err := s.Store.OperationPrincipal(ctx, a, scope.EnvironmentID)
		if err != nil {
			return err
		}
		summary, err := s.summary(ctx, p, now.Add(-24*time.Hour), now)
		if err != nil {
			return err
		}
		// Exception inventory is scoped and paged. Exceeded page count is visible.
		page, err := ruleinventory.Exceptions(auth.WithPrincipal(ctx, p), s.Store, nil, a.ID, scope.EnvironmentID, "", now)
		if err != nil {
			return err
		}
		expiring := 0
		seen := map[string]bool{}
		for _, e := range page.Exceptions {
			key := e.PolicyID + "/" + e.Exception.ID
			if seen[key] {
				continue
			}
			for _, w := range e.Warnings {
				if w == "expired" || w == "expiring" {
					expiring++
					seen[key] = true
					break
				}
			}
		}
		state := "healthy"
		if expiring > 0 {
			state = "degraded"
		}
		if page.Next != "" {
			if expiring == 0 {
				state = "unknown"
			}
			summary.Truncated = true
		}
		summary.Signals = append(summary.Signals, Signal{Kind: "exception_expiry", State: state, Affected: expiring})
		if err = s.observe(ctx, a.ID, scope.EnvironmentID, a.Etag, summary); err != nil {
			return err
		}
	}
	if len(scopes) == 10 {
		last := scopes[len(scopes)-1]
		s.cursor = last.ApplicationID + "/" + last.EnvironmentID
	} else {
		s.cursor = ""
	}
	for range 5 {
		schedule, err := s.Store.ClaimApplicationReport(ctx, now)
		if errors.Is(err, store.ErrNotFound) {
			break
		}
		if err != nil {
			return err
		}
		a, err := s.Store.GetApplication(ctx, schedule.ApplicationID)
		if err != nil {
			return err
		}
		if a.Etag != schedule.ScopeEtag {
			if err = s.Store.PauseChangedReportScope(ctx, schedule); err != nil {
				return err
			}
			continue
		}
		p, err := s.Store.OperationPrincipal(ctx, a, schedule.EnvironmentID)
		if err != nil {
			return err
		}
		summary, err := s.summary(ctx, p, schedule.NextRun.Add(-time.Duration(schedule.EveryHours)*time.Hour), schedule.NextRun)
		if err != nil {
			return err
		}
		body, err := json.Marshal(summary)
		if err != nil {
			return err
		}
		if err = s.Store.FinishApplicationReport(ctx, schedule, body, s.now(), s.Outbound); err != nil {
			return err
		}
	}
	return nil
}
func (s *Service) observe(ctx context.Context, app, env, scope string, v Summary) error {
	for _, signal := range v.Signals {
		if err := s.Store.ObserveIncident(ctx, store.Incident{ApplicationID: app, EnvironmentID: env, ScopeEtag: scope, Kind: signal.Kind, SignalState: signal.State, Affected: signal.Affected, ObservedAt: v.ObservedAt}, s.Outbound); err != nil {
			return err
		}
	}
	return nil
}
