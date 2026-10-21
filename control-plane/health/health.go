// Package health collects bounded, non-sensitive operational observations.
package health

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/strata/strata/control-plane/auth"
	"github.com/strata/strata/control-plane/ingest"
	"github.com/strata/strata/control-plane/store"
)

func check(id, state string, at *time.Time, value *string, unit string) Check {
	return Check{ID: id, State: state, ObservedAt: at, Value: value, Unit: unit, Advice: id}
}
func count(id string, value uint64, at *time.Time, now time.Time, warn bool) Check {
	state := Healthy
	if at == nil {
		return check(id, Unknown, nil, nil, "count")
	} else if now.Sub(*at) > Freshness || at.After(now.Add(5*time.Second)) {
		state = Stale
	} else if warn {
		state = Degraded
	}
	text := strconv.FormatUint(value, 10)
	return check(id, state, at, &text, "count")
}
func unknown(id string) Check { return check(id, Unknown, nil, nil, "") }
func (s *Service) Collect(ctx context.Context, p *auth.Principal) Snapshot {
	now := time.Now().UTC()
	if s.Now != nil {
		now = s.Now().UTC()
	}
	out := Snapshot{At: now, FreshForSeconds: int64(Freshness / time.Second), Version: s.Version, Scope: "global", Checks: []Check{}, Nodes: []Node{}}
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	if p != nil {
		ctx = auth.WithPrincipal(ctx, p)
	}
	scoped := p != nil && p.Access != nil
	traffic := p == nil || p.Can(auth.PermEventsRead)
	if scoped {
		out.Scope = "applications"
	}
	if s.Ready != nil {
		states, _ := s.Ready(ctx)
		for _, id := range []string{"postgres", "lease", "clickhouse"} {
			state := Unknown
			switch states[id] {
			case "ok", "held":
				state = Healthy
			case "error", "degraded", "lost", "expired":
				state = Unavailable
			}
			out.Checks = append(out.Checks, check(id, state, &now, nil, ""))
		}
	} else {
		for _, id := range []string{"postgres", "lease", "clickhouse"} {
			out.Checks = append(out.Checks, unknown(id))
		}
	}
	if !scoped && s.FreeBytes != nil {
		free, err := s.FreeBytes()
		if err != nil {
			out.Checks = append(out.Checks, check("artifact_disk", Unavailable, &now, nil, ""))
		} else {
			c := count("artifact_disk", free, &now, now, free < 2<<30)
			c.Unit = "bytes"
			out.Checks = append(out.Checks, c)
		}
	} else {
		out.Checks = append(out.Checks, unknown("artifact_disk"))
	}
	// Remote database disks cannot be inferred from this process's filesystem.
	out.Checks = append(out.Checks, unknown("postgres_disk"), unknown("clickhouse_disk"))
	if !scoped && traffic && s.Ingest != nil {
		stats := s.Ingest()
		if stats != nil {
			out.Checks = append(out.Checks, count("ingest_queue", uint64(max(0, stats.BufferQueueLen)), &now, now, stats.BufferQueueLen > 0), count("invalid_events", stats.TotalEventsInvalid, &now, now, stats.TotalEventsInvalid > 0))
		} else {
			out.Checks = append(out.Checks, unknown("ingest_queue"), unknown("invalid_events"))
		}
	} else {
		out.Checks = append(out.Checks, unknown("ingest_queue"), unknown("invalid_events"))
	}

	if delivery, ok := s.Events.(interface {
		DeliveryHealth(context.Context) (ingest.DeliveryHealth, error)
	}); ok && traffic {
		d, err := delivery.DeliveryHealth(ctx)
		if err != nil {
			out.Checks = append(out.Checks, check("ingest_lag", Unavailable, &now, nil, ""))
		} else if d.MaxLagSeconds == nil {
			out.Checks = append(out.Checks, unknown("ingest_lag"))
		} else {
			c := count("ingest_lag", *d.MaxLagSeconds, d.ObservedAt, now, *d.MaxLagSeconds > 30)
			c.Unit = "seconds"
			out.Checks = append(out.Checks, c, count("event_clock_skew", d.ClockSkewEvents, d.ObservedAt, now, d.ClockSkewEvents > 0))
		}
	} else {
		out.Checks = append(out.Checks, unknown("ingest_lag"))
	}
	if traffic {
		s.inspection(ctx, &out, now)
	} else {
		for _, id := range []string{"requests", "not_inspected", "body_skipped", "breaker", "shadow_events"} {
			out.Checks = append(out.Checks, unknown(id))
		}
	}
	if s.Store == nil {
		out.Checks = append(out.Checks, unknown("fleet"), unknown("failed_operations"))
		return out
	}
	var ids, policies []string
	if scoped {
		ids = []string{}
		policies = []string{}
		for resource, perms := range p.Access.Resources {
			if strings.HasPrefix(resource, "nodes/") && perms[auth.PermNodesRead] {
				ids = append(ids, strings.TrimPrefix(resource, "nodes/"))
			}
			if strings.HasPrefix(resource, "policies/") && perms[auth.PermPoliciesRead] {
				policies = append(policies, strings.TrimPrefix(resource, "policies/"))
			}
		}
	}
	if p == nil || p.Can(auth.PermPoliciesRead) {
		failures, err := s.Store.FailedOperationsSince(ctx, now.Add(-24*time.Hour), policies)
		if err != nil {
			out.Checks = append(out.Checks, check("failed_operations", Unavailable, &now, nil, ""))
		} else {
			out.Checks = append(out.Checks, count("failed_operations", failures, &now, now, failures > 0))
		}
	} else {
		out.Checks = append(out.Checks, unknown("failed_operations"))
	}

	nodes, truncated, err := s.Store.HealthNodes(ctx, ids)
	if err != nil {
		out.Checks = append(out.Checks, check("fleet", Unavailable, &now, nil, ""))
		return out
	}
	out.Truncated = truncated
	if len(nodes) == 0 {
		out.Checks = append(out.Checks, unknown("fleet"))
	} else {
		state := Healthy
		if truncated {
			state = Degraded
		}
		out.Checks = append(out.Checks, check("fleet", state, &now, nil, ""))
	}
	for _, n := range nodes {
		out.Nodes = append(out.Nodes, nodeHealth(n, now, scoped || !traffic))
	}
	return out
}
func (s *Service) inspection(ctx context.Context, out *Snapshot, now time.Time) {
	ids := []string{"requests", "not_inspected", "body_skipped", "breaker", "shadow_events"}
	source, ok := s.Events.(interface {
		InspectionHealth(context.Context, time.Time) (ingest.InspectionHealth, error)
	})
	if !ok {
		for _, id := range ids {
			out.Checks = append(out.Checks, unknown(id))
		}
		return
	}
	data, err := source.InspectionHealth(ctx, now)
	if err != nil {
		for _, id := range ids {
			out.Checks = append(out.Checks, check(id, Unavailable, &now, nil, ""))
		}
		return
	}
	if data.Scoped {
		for _, id := range ids[:4] {
			out.Checks = append(out.Checks, unknown(id))
		}
	} else {
		for _, c := range []Check{count("requests", data.Requests, data.ObservedAt, now, false), count("not_inspected", data.NotInspected, data.ObservedAt, now, data.NotInspected > 0), count("body_skipped", data.BodySkipped, data.ObservedAt, now, data.BodySkipped > 0), count("breaker", data.Breaker, data.ObservedAt, now, data.Breaker > 0)} {
			c.Unit = "requests_15m"
			out.Checks = append(out.Checks, c)
		}
	}
	c := count("shadow_events", data.Shadow, &now, now, false)
	c.Unit = "events_15m"
	out.Checks = append(out.Checks, c)
}
func nodeHealth(n store.HealthNode, now time.Time, scoped bool) Node {
	out := Node{ID: n.ID, Checks: []Check{}}
	online := Healthy
	if n.LastSeen == nil || !n.Connected || now.Sub(*n.LastSeen) > 30*time.Second || n.LastSeen.After(now.Add(5*time.Second)) {
		online = Degraded
	}
	out.Checks = append(out.Checks, check("heartbeat", online, n.LastSeen, nil, ""))
	if n.Actual == nil || n.Desired == nil {
		out.Checks = append(out.Checks, unknown("bundle_drift"))
	} else {
		v := strconv.FormatInt(*n.Actual, 10) + "/" + strconv.FormatInt(*n.Desired, 10)
		state := Healthy
		if *n.Actual != *n.Desired {
			state = Degraded
		}
		if n.LastSeen == nil || now.Sub(*n.LastSeen) > Freshness {
			state = Stale
		}
		out.Checks = append(out.Checks, check("bundle_drift", state, n.LastSeen, &v, "actual/desired"))
	}
	state := store.CertificateStatus(n.CertNotAfter, now)
	certState := Healthy
	if state == "unknown" {
		certState = Unknown
	} else if state != "healthy" {
		certState = Degraded
	}
	out.Checks = append(out.Checks, check("certificate", certState, &now, &state, ""))
	if scoped || n.Telemetry == nil {
		for _, id := range []string{"fail_open", "dropped_events", "spool_bytes", "spool_capacity", "spool_pending", "spool_dropped"} {
			out.Checks = append(out.Checks, unknown(id))
		}
		return out
	}
	if n.Telemetry.MetricsAvailable {
		out.Checks = append(out.Checks, count("fail_open", n.Telemetry.FailOpen, n.TelemetryAt, now, n.Telemetry.FailOpen > 0), count("dropped_events", n.Telemetry.DroppedEvents, n.TelemetryAt, now, n.Telemetry.DroppedEvents > 0))
	} else {
		out.Checks = append(out.Checks, unknown("fail_open"), unknown("dropped_events"))
	}
	if sp := n.Telemetry.Spool; sp != nil {
		c := count("spool_bytes", sp.Bytes, n.TelemetryAt, now, sp.LimitBytes > 0 && float64(sp.Bytes)/float64(sp.LimitBytes) > .8)
		c.Unit = "bytes"
		capacity := count("spool_capacity", sp.LimitBytes, n.TelemetryAt, now, false)
		capacity.Unit = "bytes"
		if sp.LimitBytes == 0 {
			capacity.State = Unknown
		}
		out.Checks = append(out.Checks, c, capacity, count("spool_pending", sp.PendingBatches, n.TelemetryAt, now, sp.PendingBatches > 0), count("spool_dropped", sp.DroppedEvents, n.TelemetryAt, now, sp.DroppedEvents > 0))
	} else {
		for _, id := range []string{"spool_bytes", "spool_capacity", "spool_pending", "spool_dropped"} {
			out.Checks = append(out.Checks, unknown(id))
		}
	}
	return out
}
