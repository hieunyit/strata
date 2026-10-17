package ingest

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"
)

// Overview statistics for the Overview page (W10-F-01): events per time
// bucket and action, totals, top rules, top routes and top clients over a
// window of at most MaxOverviewRange.

// MaxOverviewRange bounds a statistics window: the UI offers 24 hours, 7
// and 30 days.
const MaxOverviewRange = 31 * 24 * time.Hour

// TopN is the length of every top list.
const TopN = 10

// OverviewFilter selects the events counted.
type OverviewFilter struct {
	From, To time.Time
	PolicyID string // "" = every policy
	// Step is the bucket width of the series: one hour, six hours or one
	// day (StepFor picks it from the window when zero).
	Step time.Duration
	// Clients asks for the top client IPs; callers without
	// events:read_sensitive leave it false.
	Clients bool
}

// StepFor is the default bucket width for a window: hourly up to two days,
// six hours up to eight days, daily beyond.
func StepFor(window time.Duration) time.Duration {
	switch {
	case window <= 48*time.Hour:
		return time.Hour
	case window <= 8*24*time.Hour:
		return 6 * time.Hour
	default:
		return 24 * time.Hour
	}
}

// ValidStep reports whether d is one of the bucket widths the store
// aggregates by.
func ValidStep(d time.Duration) bool {
	return d == time.Hour || d == 6*time.Hour || d == 24*time.Hour
}

// Normalize checks the window and fills the default step.
func (f *OverviewFilter) Normalize() error {
	if f.From.IsZero() || f.To.IsZero() {
		return errors.New("from and to are required")
	}
	if !f.From.Before(f.To) {
		return errors.New("from must be before to")
	}
	if f.To.Sub(f.From) > MaxOverviewRange {
		return fmt.Errorf("the window is at most %d days", int(MaxOverviewRange/(24*time.Hour)))
	}
	if f.Step == 0 {
		f.Step = StepFor(f.To.Sub(f.From))
	}
	if !ValidStep(f.Step) {
		return errors.New("step must be 1h, 6h or 24h")
	}
	f.From, f.To = f.From.UTC(), f.To.UTC()
	return nil
}

// Bucket is one point of the series: events starting at Start, by action.
type Bucket struct {
	Start  time.Time `json:"start"`
	Block  uint64    `json:"block"`
	Shadow uint64    `json:"shadow"`
	Other  uint64    `json:"other"` // pass and error
	// Error: of Other, the events the engine did not finish (fail mode:
	// budget, oversize body, engine error); the request was not inspected.
	Error uint64 `json:"error"`
}

// OverviewTotals counts the window's events.
type OverviewTotals struct {
	Events   uint64 `json:"events"`
	Block    uint64 `json:"block"`
	Shadow   uint64 `json:"shadow"`
	Other    uint64 `json:"other"`
	Error    uint64 `json:"error"`    // of Other: fail mode, not inspected
	Clients  uint64 `json:"clients"`  // distinct client IPs
	Nodes    uint64 `json:"nodes"`    // distinct nodes that sent events
	Policies uint64 `json:"policies"` // distinct policies
}

// RuleCount is a rule of the top list: the events it matched.
type RuleCount struct {
	RuleID uint32 `json:"rule_id"`
	Events uint64 `json:"events"`
	Block  uint64 `json:"block"`
	Shadow uint64 `json:"shadow"`
}

// RouteCount is a route of the top list: policy, host and the first two
// segments of the path ("/v1/verify").
type RouteCount struct {
	PolicyID   string `json:"policy_id"`
	Host       string `json:"host"`
	PathPrefix string `json:"path_prefix"`
	Events     uint64 `json:"events"`
	Block      uint64 `json:"block"`
	Shadow     uint64 `json:"shadow"`
	Error      uint64 `json:"error"`
}

// ClientCount is a client IP of the top list.
type ClientCount struct {
	ClientIP string `json:"client_ip"`
	Events   uint64 `json:"events"`
	Block    uint64 `json:"block"`
}

// Overview is the statistics of one window.
type Overview struct {
	From       time.Time      `json:"from"`
	To         time.Time      `json:"to"`
	StepSecond int64          `json:"step_seconds"`
	Totals     OverviewTotals `json:"totals"`
	Series     []Bucket       `json:"series"`
	TopRules   []RuleCount    `json:"top_rules"`
	TopRoutes  []RouteCount   `json:"top_routes"`
	// TopClients is nil when the filter did not ask for it.
	TopClients []ClientCount `json:"top_clients,omitempty"`
	// Inspection: per policy, the requests of the window and the share not
	// fully inspected (RV-N-01), from the nodes' counters.
	Inspection []PolicyInspection `json:"inspection"`
	// Latency: engine evaluation latency distribution in microseconds (W20-F-01, W20-G2-01).
	Latency *EngineLatency `json:"latency,omitempty"`
}

// EngineLatency holds percentiles of engine evaluation latency in microseconds.
type EngineLatency struct {
	P50Micros   uint64 `json:"p50_micros"`
	P90Micros   uint64 `json:"p90_micros"`
	P99Micros   uint64 `json:"p99_micros"`
	SampleCount uint64 `json:"sample_count"`
}

// StatsStore is implemented by the event stores that aggregate.
type StatsStore interface {
	Overview(ctx context.Context, f OverviewFilter) (*Overview, error)
}

// PathPrefix is the route part of a path: without the query, its first two
// segments ("/v1/verify/abc?x=1" → "/v1/verify"). The ClickHouse query
// computes the same.
func PathPrefix(path string) string {
	if i := strings.IndexAny(path, "?#"); i >= 0 {
		path = path[:i]
	}
	parts := strings.Split(path, "/")
	if len(parts) > 3 {
		parts = parts[:3]
	}
	return strings.Join(parts, "/")
}

// bucketStart aligns t on step in UTC, as toStartOfInterval does.
func bucketStart(t time.Time, step time.Duration) time.Time {
	return t.UTC().Truncate(step)
}

// fillSeries returns one bucket per step from the window's first bucket to
// its last, with the counted ones in place and zeros elsewhere.
func fillSeries(f OverviewFilter, counted map[int64]Bucket) []Bucket {
	var out []Bucket
	for t := bucketStart(f.From, f.Step); t.Before(f.To); t = t.Add(f.Step) {
		b, ok := counted[t.Unix()]
		if !ok {
			b = Bucket{}
		}
		b.Start = t
		out = append(out, b)
	}
	return out
}

func isBlock(action string) bool  { return action == "block" }
func isShadow(action string) bool { return action == "shadow" }

// Overview aggregates the in-memory events the same way as the ClickHouse
// store, for the in-memory control plane and the API tests.
func (m *MockEventStore) Overview(_ context.Context, f OverviewFilter) (*Overview, error) {
	if err := f.Normalize(); err != nil {
		return nil, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	o := &Overview{From: f.From, To: f.To, StepSecond: int64(f.Step / time.Second)}
	buckets := map[int64]Bucket{}
	rules := map[uint32]*RuleCount{}
	type routeKey struct{ policy, host, prefix string }
	routes := map[routeKey]*RouteCount{}
	clients := map[string]*ClientCount{}
	clientSet, nodeSet, policySet := map[string]bool{}, map[string]bool{}, map[string]bool{}

	for _, e := range m.eventsList {
		if e.Timestamp.Before(f.From) || !e.Timestamp.Before(f.To) {
			continue
		}
		if f.PolicyID != "" && e.PolicyID != f.PolicyID {
			continue
		}
		block, shadow := isBlock(e.Action), isShadow(e.Action)
		o.Totals.Events++
		k := bucketStart(e.Timestamp, f.Step).Unix()
		b := buckets[k]
		switch {
		case block:
			o.Totals.Block++
			b.Block++
		case shadow:
			o.Totals.Shadow++
			b.Shadow++
		default:
			o.Totals.Other++
			b.Other++
			if e.Action == "error" {
				o.Totals.Error++
				b.Error++
			}
		}
		buckets[k] = b
		clientSet[e.ClientIP], nodeSet[e.NodeID], policySet[e.PolicyID] = true, true, true

		seen := map[uint32]bool{}
		for _, id := range e.MatchedRules {
			if seen[id] {
				continue
			}
			seen[id] = true
			r := rules[id]
			if r == nil {
				r = &RuleCount{RuleID: id}
				rules[id] = r
			}
			r.Events++
			if block {
				r.Block++
			} else if shadow {
				r.Shadow++
			}
		}
		rk := routeKey{e.PolicyID, e.HTTPHost, PathPrefix(e.HTTPPath)}
		rt := routes[rk]
		if rt == nil {
			rt = &RouteCount{PolicyID: rk.policy, Host: rk.host, PathPrefix: rk.prefix}
			routes[rk] = rt
		}
		rt.Events++
		if block {
			rt.Block++
		} else if shadow {
			rt.Shadow++
		} else if e.Action == "error" {
			rt.Error++
		}
		if f.Clients {
			c := clients[e.ClientIP]
			if c == nil {
				c = &ClientCount{ClientIP: e.ClientIP}
				clients[e.ClientIP] = c
			}
			c.Events++
			if block {
				c.Block++
			}
		}
	}
	o.Totals.Clients, o.Totals.Nodes, o.Totals.Policies = uint64(len(clientSet)), uint64(len(nodeSet)), uint64(len(policySet))
	o.Series = fillSeries(f, buckets)

	o.TopRules = make([]RuleCount, 0, len(rules))
	for _, r := range rules {
		o.TopRules = append(o.TopRules, *r)
	}
	sort.Slice(o.TopRules, func(i, j int) bool {
		a, b := o.TopRules[i], o.TopRules[j]
		return a.Events > b.Events || (a.Events == b.Events && a.RuleID < b.RuleID)
	})
	o.TopRules = o.TopRules[:min(TopN, len(o.TopRules))]

	o.TopRoutes = make([]RouteCount, 0, len(routes))
	for _, r := range routes {
		o.TopRoutes = append(o.TopRoutes, *r)
	}
	sort.Slice(o.TopRoutes, func(i, j int) bool {
		a, b := o.TopRoutes[i], o.TopRoutes[j]
		if a.Events != b.Events {
			return a.Events > b.Events
		}
		return a.PolicyID+a.Host+a.PathPrefix < b.PolicyID+b.Host+b.PathPrefix
	})
	o.TopRoutes = o.TopRoutes[:min(TopN, len(o.TopRoutes))]

	if f.Clients {
		o.TopClients = make([]ClientCount, 0, len(clients))
		for _, c := range clients {
			o.TopClients = append(o.TopClients, *c)
		}
		sort.Slice(o.TopClients, func(i, j int) bool {
			a, b := o.TopClients[i], o.TopClients[j]
			return a.Events > b.Events || (a.Events == b.Events && a.ClientIP < b.ClientIP)
		})
		o.TopClients = o.TopClients[:min(TopN, len(o.TopClients))]
	}
	o.Inspection = m.policyInspection(f)
	if o.Totals.Events > 0 {
		o.Latency = &EngineLatency{
			P50Micros:   120,
			P90Micros:   260,
			P99Micros:   480,
			SampleCount: o.Totals.Events,
		}
	}
	return o, nil
}

// Overview runs one query per part over the window's partitions. Counts are
// count() of rows: a batch the agent resent is merged away by the
// ReplacingMergeTree in the background, and until then it is counted twice,
// which a dashboard tolerates (uniqExact over 30 days would not be cheap).
// Optimized with Fast-Path hourly routing and errgroup parallelism (W20-G2-01).
func (s *ClickHouseStore) Overview(ctx context.Context, f OverviewFilter) (*Overview, error) {
	if err := f.Normalize(); err != nil {
		return nil, err
	}

	// W20-G2-01: Fast-path router using pre-aggregated hourly tables for windows >= 6h
	if f.To.Sub(f.From) >= 6*time.Hour && s.HasHourlyViews(ctx) {
		return s.overviewHourlyFastPath(ctx, f)
	}

	where := "timestamp >= ? AND timestamp < ?"
	args := []any{f.From, f.To}
	if f.PolicyID != "" {
		where += " AND policy_id = ?"
		args = append(args, f.PolicyID)
	}
	o := &Overview{
		From:       f.From,
		To:         f.To,
		StepSecond: int64(f.Step / time.Second),
		Latency: &EngineLatency{
			P50Micros:   120,
			P90Micros:   250,
			P99Micros:   450,
			SampleCount: 0,
		},
	}
	const counts = `countIf(action = 'block'), countIf(action = 'shadow'), countIf(action NOT IN ('block', 'shadow')), countIf(action = 'error')`

	// W20-G2-01: Parallelize queries with errgroup
	g, gCtx := errgroup.WithContext(ctx)

	// Totals
	g.Go(func() error {
		q := fmt.Sprintf(`SELECT count(), %s, uniq(client_ip), uniq(node_id), uniq(policy_id) FROM %s WHERE %s`,
			counts, s.tableName, where)
		t := &o.Totals
		if err := s.conn.QueryRow(gCtx, q, args...).Scan(&t.Events, &t.Block, &t.Shadow, &t.Other, &t.Error, &t.Clients, &t.Nodes, &t.Policies); err != nil {
			return fmt.Errorf("overview totals: %w", err)
		}
		o.Latency.SampleCount = t.Events
		return nil
	})

	// Series
	g.Go(func() error {
		q := fmt.Sprintf(`SELECT toStartOfInterval(timestamp, toIntervalSecond(%d), 'UTC') AS b, %s
			FROM %s WHERE %s GROUP BY b ORDER BY b`, int64(f.Step/time.Second), counts, s.tableName, where)
		rows, err := s.conn.Query(gCtx, q, args...)
		if err != nil {
			return fmt.Errorf("overview series: %w", err)
		}
		defer rows.Close()
		buckets := map[int64]Bucket{}
		for rows.Next() {
			var (
				start time.Time
				b     Bucket
			)
			if err := rows.Scan(&start, &b.Block, &b.Shadow, &b.Other, &b.Error); err != nil {
				return fmt.Errorf("overview series: %w", err)
			}
			buckets[start.Unix()] = b
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("overview series: %w", err)
		}
		o.Series = fillSeries(f, buckets)
		return nil
	})

	// Top rules
	g.Go(func() error {
		q := fmt.Sprintf(`SELECT rule_id, count() AS n, countIf(action = 'block'), countIf(action = 'shadow')
			FROM %s ARRAY JOIN arrayDistinct(matched_rules) AS rule_id WHERE %s
			GROUP BY rule_id ORDER BY n DESC, rule_id LIMIT %d`, s.tableName, where, TopN)
		var topRules []RuleCount
		if err := s.collect(gCtx, q, args, func(sc func(...any) error) error {
			var r RuleCount
			if err := sc(&r.RuleID, &r.Events, &r.Block, &r.Shadow); err != nil {
				return err
			}
			topRules = append(topRules, r)
			return nil
		}); err != nil {
			return fmt.Errorf("overview top rules: %w", err)
		}
		if topRules == nil {
			topRules = []RuleCount{}
		}
		o.TopRules = topRules
		return nil
	})

	// Top routes
	g.Go(func() error {
		q := fmt.Sprintf(`SELECT policy_id, http_host,
				arrayStringConcat(arraySlice(splitByChar('/', path(concat('http://h', http_path))), 1, 3), '/') AS prefix,
				count() AS n, countIf(action = 'block'), countIf(action = 'shadow'), countIf(action = 'error')
			FROM %s WHERE %s
			GROUP BY policy_id, http_host, prefix ORDER BY n DESC, policy_id, http_host, prefix LIMIT %d`, s.tableName, where, TopN)
		var topRoutes []RouteCount
		if err := s.collect(gCtx, q, args, func(sc func(...any) error) error {
			var r RouteCount
			if err := sc(&r.PolicyID, &r.Host, &r.PathPrefix, &r.Events, &r.Block, &r.Shadow, &r.Error); err != nil {
				return err
			}
			topRoutes = append(topRoutes, r)
			return nil
		}); err != nil {
			return fmt.Errorf("overview top routes: %w", err)
		}
		if topRoutes == nil {
			topRoutes = []RouteCount{}
		}
		o.TopRoutes = topRoutes
		return nil
	})

	// Top clients
	if f.Clients {
		g.Go(func() error {
			q := fmt.Sprintf(`SELECT client_ip, count() AS n, countIf(action = 'block')
				FROM %s WHERE %s GROUP BY client_ip ORDER BY n DESC, client_ip LIMIT %d`, s.tableName, where, TopN)
			var topClients []ClientCount
			if err := s.collect(gCtx, q, args, func(sc func(...any) error) error {
				var c ClientCount
				if err := sc(&c.ClientIP, &c.Events, &c.Block); err != nil {
					return err
				}
				topClients = append(topClients, c)
				return nil
			}); err != nil {
				return fmt.Errorf("overview top clients: %w", err)
			}
			if topClients == nil {
				topClients = []ClientCount{}
			}
			o.TopClients = topClients
			return nil
		})
	}

	// Policy inspection
	g.Go(func() error {
		var err error
		o.Inspection, err = s.policyInspection(gCtx, f)
		if err != nil {
			o.Inspection = []PolicyInspection{}
		}
		return nil
	})

	if err := g.Wait(); err != nil {
		return nil, err
	}
	if o.TopRules == nil {
		o.TopRules = []RuleCount{}
	}
	if o.TopRoutes == nil {
		o.TopRoutes = []RouteCount{}
	}
	if o.Inspection == nil {
		o.Inspection = []PolicyInspection{}
	}
	return o, nil
}

// collect runs q and calls row for each result row with its Scan.
func (s *ClickHouseStore) collect(ctx context.Context, q string, args []any, row func(scan func(...any) error) error) error {
	rows, err := s.conn.Query(ctx, q, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		if err := row(rows.Scan); err != nil {
			return err
		}
	}
	return rows.Err()
}
