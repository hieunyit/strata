package fleet

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"log"
	"math"
	"strings"
	"sync"
	"time"

	eventv1 "github.com/strata/strata/agent/gen/strata/event/v1"
	fleetv1 "github.com/strata/strata/agent/gen/strata/fleet/v1"
	"github.com/strata/strata/agent/pkg/stats"
	"github.com/strata/strata/control-plane/store"
)

// Cluster tier of the automatic fallback (nginx-module.md › Bật enforce theo
// canary, "Tự fallback hai tầng", tier 2; W12-G2-01). Agents send the
// counters of the two canary groups of their node in every heartbeat (15 s):
// the requests of policies with an enforce canary, inside the canary
// (enforced) and outside it (shadow). Per connector group, over the last
// minute, the monitor compares the two (PO decisions 14/10/2026):
//
//   - upstream 5xx: canary rate at least 1 point over the shadow rate and at
//     least twice it;
//   - p99 latency: canary at least 1.5 times the shadow p99 and 50 ms more;
//   - blocks: the two groups split clients at random, so a policy that
//     blocks by mistake moves both the same way. The canary's block rate is
//     compared with the "would block" level of the canary policies learnt
//     over the last hour instead (blocks + would-be blocks logged, both
//     groups; a moving average over the windows that did not trip): over 3
//     times that level and over 1%, and improbable under it (one-sided
//     Poisson test, p < 1e-6).
//
//     #74: the blocks and would-be blocks are counted from the events the
//     nodes send (ObserveEvent: client address, canary side), at most 3 per
//     client address (IPv6 per /64) and window over the whole group: a few
//     clients sending a flood of blocked payloads through every node cannot
//     force the group's canary policies into shadow; a policy blocking real
//     users blocks many addresses. The requests stay the heartbeat
//     counters. A real attack from many addresses (a botnet) can still
//     trip it; events lost on the way only lower the counts.
//
// Each group needs 200 requests in the window. On a trip every canary
// policy (current version with canary_percent) is forced into shadow on
// every node of the group (ForceShadow, 24 h, renewed every 12 h), running
// rollouts pause, and the trip is audited and counted. It holds until
// clearForceShadow lifts its policies (admin API).

// CanaryStore is the part of store.Store the monitor uses.
type CanaryStore interface {
	CanaryPolicies(ctx context.Context) ([]string, error)
	GroupNodes(ctx context.Context, group string) ([]string, error)
	OpenCanaryTrip(ctx context.Context, t store.CanaryTrip, cmds []store.Command, a store.Audit) (store.CanaryTrip, []store.Command, error)
	OpenCanaryTrips(ctx context.Context) ([]store.CanaryTrip, error)
	RenewCanaryTrip(ctx context.Context, id int64, cmds []store.Command, at time.Time) ([]store.Command, error)
	ActiveRollouts(ctx context.Context) ([]store.Rollout, error)
	SetRolloutState(ctx context.Context, id int64, to, reason string, from []string, a store.Audit) (store.Rollout, error)
}

// Trip reasons.
const (
	TripBlockRate = "block_rate"
	Trip5xx       = "upstream_5xx"
	TripLatency   = "latency"
)

// CanaryOptions; zero values take the defaults.
type CanaryOptions struct {
	Window      time.Duration // 1 min
	Interval    time.Duration // between two evaluations, 5 s
	MinRequests uint64        // per group and window, 200
	Learn       time.Duration // time constant of the block level, 1 h
	Warmup      int           // evaluations learnt before blocks may trip, 12
	BlockFactor float64       // 3
	BlockFloor  float64       // 1%
	PValue      float64       // Poisson tail a block count must be under, 1e-6 (#74)
	SourceCap   uint64        // blocks of one client address counted per window, 3 (#74)
	MaxSources  int           // addresses tracked per group and interval, 4096; each further one counts once
	Renew       time.Duration // 12 h
	Hold        time.Duration // ForceShadow duration, 24 h (the most a command takes)
}

func (o CanaryOptions) withDefaults() CanaryOptions {
	def := func(d *time.Duration, v time.Duration) {
		if *d <= 0 {
			*d = v
		}
	}
	def(&o.Window, time.Minute)
	def(&o.Interval, 5*time.Second)
	def(&o.Learn, time.Hour)
	def(&o.Renew, 12*time.Hour)
	def(&o.Hold, MaxForceShadowDuration)
	if o.MinRequests == 0 {
		o.MinRequests = 200
	}
	if o.Warmup <= 0 {
		o.Warmup = 12
	}
	if o.BlockFactor <= 0 {
		o.BlockFactor = 3
	}
	if o.BlockFloor <= 0 {
		o.BlockFloor = 0.01
	}
	if o.PValue <= 0 || o.PValue >= 1 {
		o.PValue = 1e-6
	}
	if o.SourceCap == 0 {
		o.SourceCap = 3
	}
	if o.MaxSources <= 0 {
		o.MaxSources = 4096
	}
	return o
}

// MaxForceShadowDuration: the longest ForceShadow a node accepts.
const MaxForceShadowDuration = 24 * time.Hour

// latencyBounds of the canary histogram, seconds (the last bucket is +Inf).
var latencyBounds = []float64{5e-3, 10e-3, 25e-3, 50e-3, 100e-3, 250e-3, 500e-3, 1}

type groupCounts struct {
	req, blocked, logged, x5 uint64
	lat                      [9]uint64
}

func countsOf(c *fleetv1.CanaryCounters) groupCounts {
	g := groupCounts{req: c.GetRequests(), blocked: c.GetBlocked(), logged: c.GetLogged(), x5: c.GetUpstreamServerErrors()}
	for i, n := range c.GetLatency() {
		if i < len(g.lat) {
			g.lat[i] = n
		}
	}
	return g
}

// sub: g - o, false when a counter went down.
func (g groupCounts) sub(o groupCounts) (groupCounts, bool) {
	ok := g.req >= o.req && g.blocked >= o.blocked && g.logged >= o.logged && g.x5 >= o.x5
	d := groupCounts{req: g.req - o.req, blocked: g.blocked - o.blocked, logged: g.logged - o.logged, x5: g.x5 - o.x5}
	for i := range g.lat {
		ok = ok && g.lat[i] >= o.lat[i]
		d.lat[i] = g.lat[i] - o.lat[i]
	}
	return d, ok
}

func (g *groupCounts) add(o groupCounts) {
	g.req += o.req
	g.blocked += o.blocked
	g.logged += o.logged
	g.x5 += o.x5
	for i := range g.lat {
		g.lat[i] += o.lat[i]
	}
}

// p99 in seconds: the upper bound of the bucket holding the 99th
// percentile (2 s for +Inf).
func (g groupCounts) p99() float64 {
	var n uint64
	for _, c := range g.lat {
		n += c
	}
	if n == 0 {
		return 0
	}
	want := uint64(math.Ceil(0.99 * float64(n)))
	var cum uint64
	for i, c := range g.lat {
		cum += c
		if cum >= want {
			if i < len(latencyBounds) {
				return latencyBounds[i]
			}
			break
		}
	}
	return 2
}

type nodeSample struct {
	group   string
	created uint64
	c, s    groupCounts
}

type canaryDelta struct {
	at   time.Time
	c, s groupCounts
}

// sourceBucket: one interval's blocks and would-be blocks by client
// address (#74): [canary blocks, canary would, shadow would].
type sourceBucket struct {
	at   time.Time
	n    map[string]*[3]uint64
	over [3]uint64 // addresses past MaxSources, one each
}

type groupState struct {
	deltas  []canaryDelta
	buckets []*sourceBucket
	ref     float64 // learnt would-block share
	learnt  int
	tripped bool
}

// CanaryMonitor runs the cluster tier. Safe for concurrent Observe calls.
type CanaryMonitor struct {
	Store CanaryStore
	Kick  interface{ Kick() } // the command dispatcher
	Now   func() time.Time
	o     CanaryOptions

	mu     sync.Mutex
	nodes  map[string]nodeSample
	groups map[string]*groupState
	trips  map[string]uint64 // by reason, since start
}

// NewCanaryMonitor returns a monitor; call Run.
func NewCanaryMonitor(st CanaryStore, kick interface{ Kick() }, o CanaryOptions) *CanaryMonitor {
	return &CanaryMonitor{Store: st, Kick: kick, Now: time.Now, o: o.withDefaults(),
		nodes: map[string]nodeSample{}, groups: map[string]*groupState{}, trips: map[string]uint64{}}
}

func (m *CanaryMonitor) group(g string) *groupState {
	st := m.groups[g]
	if st == nil {
		st = &groupState{}
		m.groups[g] = st
	}
	return st
}

// Observe takes a node's heartbeat counters. The first heartbeat of a node
// only sets its starting point; NGINX reloads (a new metrics file) start
// the counters again from 0.
func (m *CanaryMonitor) Observe(node, group string, nc *fleetv1.NodeCounters, at time.Time) {
	if group == "" || nc.GetCanary() == nil || nc.GetCanaryShadow() == nil {
		return
	}
	cur := nodeSample{group: group, created: nc.GetMetricsCreatedMs(), c: countsOf(nc.GetCanary()), s: countsOf(nc.GetCanaryShadow())}
	m.mu.Lock()
	defer m.mu.Unlock()
	prev, ok := m.nodes[node]
	m.nodes[node] = cur
	if !ok || prev.group != group {
		return
	}
	d := canaryDelta{at: at, c: cur.c, s: cur.s}
	if prev.created == cur.created {
		dc, okc := cur.c.sub(prev.c)
		ds, oks := cur.s.sub(prev.s)
		if !okc || !oks {
			return // not counters of the same file: wait for the next one
		}
		d.c, d.s = dc, ds
	}
	st := m.group(group)
	st.deltas = append(st.deltas, d)
}

// ObserveEvent counts an event a node sent (#74): a block (Block ID STR-,
// action BLOCK) or a would-be block logged in shadow (EVT-, LOG, rules,
// would_block) of a policy with an enforce canary, by client address and
// canary side. Events older than the window (a spool sent late) and nodes
// without a heartbeat yet are left out.
func (m *CanaryMonitor) ObserveEvent(node string, ev *eventv1.Event, at time.Time) {
	block := ev.GetAction() == eventv1.Action_ACTION_BLOCK && strings.HasPrefix(ev.GetBlockId(), "STR-")
	would := ev.GetAction() == eventv1.Action_ACTION_LOG && strings.HasPrefix(ev.GetBlockId(), "EVT-") &&
		len(ev.GetRuleIds()) > 0 && ev.GetWouldBlock()
	var i int // [canary blocks, canary would, shadow would]
	switch g := ev.GetCanary(); {
	case g == eventv1.CanaryGroup_CANARY_GROUP_ENFORCE && block:
		i = 0
	case g == eventv1.CanaryGroup_CANARY_GROUP_ENFORCE && would:
		i = 1
	case g == eventv1.CanaryGroup_CANARY_GROUP_SHADOW && would:
		i = 2
	default:
		return
	}
	if t := ev.GetTimeUnixMs(); t > 0 && at.Sub(time.UnixMilli(int64(t))) > m.o.Window {
		return
	}
	k := stats.SourceKey(ev.GetClientIp())
	m.mu.Lock()
	defer m.mu.Unlock()
	ns, ok := m.nodes[node]
	if !ok {
		return
	}
	st := m.group(ns.group)
	var b *sourceBucket
	if n := len(st.buckets); n > 0 && at.Sub(st.buckets[n-1].at) < m.o.Interval {
		b = st.buckets[n-1]
	} else {
		b = &sourceBucket{at: at, n: map[string]*[3]uint64{}}
		st.buckets = append(st.buckets, b)
	}
	c, ok := b.n[k]
	if !ok {
		if len(b.n) >= m.o.MaxSources {
			b.over[i]++
			return
		}
		c = new([3]uint64)
		b.n[k] = c
	}
	c[i]++
}

// bySource sums the buckets of the window, each address counted at most
// SourceCap times: canary blocks, would-be blocks of both sides (blocks
// included).
func (m *CanaryMonitor) bySource(st *groupState) (blocked, would uint64) {
	sum := map[string][3]uint64{}
	for _, b := range st.buckets {
		for k, c := range b.n {
			s := sum[k]
			for i := range s {
				s[i] += c[i]
			}
			sum[k] = s
		}
		blocked += b.over[0]
		would += b.over[0] + b.over[1] + b.over[2]
	}
	for _, c := range sum {
		blocked += min(c[0], m.o.SourceCap)
		would += min(c[0]+c[1]+c[2], m.o.SourceCap)
	}
	return blocked, would
}

// Forget drops a node (revoked, or disconnected for good).
func (m *CanaryMonitor) Forget(node string) {
	m.mu.Lock()
	delete(m.nodes, node)
	m.mu.Unlock()
}

// Trips: the trips this replica made, by reason.
func (m *CanaryMonitor) Trips() map[string]uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]uint64, len(m.trips))
	for k, v := range m.trips {
		out[k] = v
	}
	return out
}

// Run evaluates every Interval until ctx ends.
func (m *CanaryMonitor) Run(ctx context.Context) {
	t := time.NewTicker(m.o.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := m.Tick(ctx); err != nil && ctx.Err() == nil {
				log.Printf("[WARN] fleet: canary monitor: %v", err)
			}
		}
	}
}

// verdict of one group's window.
type canaryVerdict struct {
	srcBlocked, srcWould uint64 // by source (#74)
	reason               string
	detail               map[string]any
	would                float64 // would-block share of the window, to learn
	enough               bool
}

func (m *CanaryMonitor) judge(st *groupState, c, s groupCounts, srcBlocked, srcWould uint64) canaryVerdict {
	v := canaryVerdict{srcBlocked: srcBlocked, srcWould: srcWould}
	if c.req < m.o.MinRequests || s.req < m.o.MinRequests {
		return v
	}
	v.enough = true
	rate := func(a, n uint64) float64 { return float64(a) / float64(n) }
	v.would = rate(srcWould, c.req+s.req)
	c5, s5 := rate(c.x5, c.req), rate(s.x5, s.req)
	cp, sp := c.p99(), s.p99()
	// expected blocks: the learnt level, at least BlockFloor / BlockFactor
	// so that a trip is also over BlockFloor
	lambda := max(st.ref, m.o.BlockFloor/m.o.BlockFactor) * float64(c.req)
	pv := stats.PoissonTail(srcBlocked, lambda)
	v.detail = map[string]any{"canary_requests": c.req, "shadow_requests": s.req, "canary_5xx": c5, "shadow_5xx": s5,
		"canary_p99_s": cp, "shadow_p99_s": sp, "canary_block": rate(c.blocked, c.req),
		"canary_block_by_source": rate(srcBlocked, c.req), "block_p_value": pv, "would_block_ref": st.ref, "learnt": st.learnt}
	switch {
	case c5-s5 >= 0.01 && c5 >= 2*s5:
		v.reason = Trip5xx
	case cp >= 1.5*sp && cp-sp >= 0.050:
		v.reason = TripLatency
	case st.learnt >= m.o.Warmup && float64(srcBlocked) > m.o.BlockFactor*lambda && pv < m.o.PValue:
		v.reason = TripBlockRate
	}
	return v
}

// Tick evaluates every group once, renews held trips and returns the first
// store error.
func (m *CanaryMonitor) Tick(ctx context.Context) error {
	now := m.Now()
	open, err := m.Store.OpenCanaryTrips(ctx)
	if err != nil {
		return err
	}
	held := map[string]store.CanaryTrip{}
	for _, t := range open {
		held[t.GroupID] = t
	}
	type trip struct {
		group string
		v     canaryVerdict
	}
	var trips []trip
	m.mu.Lock()
	for g, st := range m.groups {
		_, isHeld := held[g]
		if st.tripped && !isHeld {
			// cleared: what the window saw belongs to the trip
			st.deltas = nil
			st.buckets = nil
		}
		st.tripped = isHeld
		cut := 0
		for cut < len(st.deltas) && now.Sub(st.deltas[cut].at) > m.o.Window {
			cut++
		}
		st.deltas = st.deltas[cut:]
		cut = 0
		for cut < len(st.buckets) && now.Sub(st.buckets[cut].at) > m.o.Window {
			cut++
		}
		st.buckets = st.buckets[cut:]
		if st.tripped {
			continue
		}
		var c, s groupCounts
		for _, d := range st.deltas {
			c.add(d.c)
			s.add(d.s)
		}
		sb, sw := m.bySource(st)
		v := m.judge(st, c, s, sb, sw)
		switch {
		case v.reason != "":
			trips = append(trips, trip{g, v})
			st.tripped = true
		case v.enough:
			a := m.o.Interval.Seconds() / m.o.Learn.Seconds()
			if st.learnt < m.o.Warmup {
				a = 1 / float64(st.learnt+1) // plain mean while warming up
			}
			st.ref += a * (v.would - st.ref)
			st.learnt++
		}
	}
	m.mu.Unlock()

	var first error
	for _, t := range trips {
		if err := m.trip(ctx, t.group, t.v, now); err != nil && first == nil {
			first = err
		}
	}
	for _, t := range open {
		if now.Sub(t.RenewedAt) >= m.o.Renew {
			if err := m.renew(ctx, t, now); err != nil && first == nil {
				first = err
			}
		}
	}
	return first
}

var cmdIDEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

func newID() (string, error) {
	b := make([]byte, 10)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "cmd-" + strings.ToLower(cmdIDEncoding.EncodeToString(b)), nil
}

func (m *CanaryMonitor) commands(nodes, policies []string, now time.Time) ([]store.Command, error) {
	var cmds []store.Command
	for _, n := range nodes {
		for _, p := range policies {
			id, err := newID()
			if err != nil {
				return nil, err
			}
			cmds = append(cmds, store.Command{ID: id, NodeID: n, Kind: store.CommandForceShadow, PolicyID: p,
				DurationSeconds: int(m.o.Hold / time.Second), ExpiresAt: now.Add(m.o.Hold).UTC()})
		}
	}
	return cmds, nil
}

const monitorActor = "canary-monitor"

func (m *CanaryMonitor) trip(ctx context.Context, group string, v canaryVerdict, now time.Time) error {
	policies, err := m.Store.CanaryPolicies(ctx)
	if err != nil {
		return err
	}
	nodes, err := m.Store.GroupNodes(ctx, group)
	if err != nil {
		return err
	}
	cmds, err := m.commands(nodes, policies, now)
	if err != nil {
		return err
	}
	a := store.Audit{Actor: monitorActor, Channel: "system", Action: "/strata.fleet.CanaryMonitor/Trip",
		Resource: "groups/" + group + ":canaryFallback"}
	t, out, err := m.Store.OpenCanaryTrip(ctx, store.CanaryTrip{GroupID: group, Reason: v.reason, Detail: v.detail,
		Policies: policies, TrippedAt: now.UTC()}, cmds, a)
	if errors.Is(err, store.ErrTripOpen) {
		return nil // another replica tripped first
	}
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.trips[v.reason]++
	m.mu.Unlock()
	if m.Kick != nil {
		m.Kick.Kick()
	}
	if len(policies) == 0 {
		log.Printf("[ERROR] fleet: canary fallback in group %s (%s): no policy of this control plane has a canary, nothing forced into shadow", group, v.reason)
	} else {
		log.Printf("[WARN] fleet: canary fallback in group %s (%s, %v): %v forced into shadow on %d nodes (%d commands), trip %d",
			group, v.reason, v.detail, policies, len(nodes), len(out), t.ID)
	}
	ros, err := m.Store.ActiveRollouts(ctx)
	if err != nil {
		return err
	}
	for _, ro := range ros {
		ra := a
		ra.Action = "/strata.fleet.CanaryMonitor/PauseRollout"
		if _, err := m.Store.SetRolloutState(ctx, ro.ID, store.RolloutPaused, "canary fallback in group "+group+": "+v.reason,
			[]string{store.RolloutRunning}, ra); err != nil && !errors.Is(err, store.ErrRolloutState) {
			return err
		}
		log.Printf("[WARN] fleet: rollout %d paused by the canary fallback", ro.ID)
	}
	return nil
}

func (m *CanaryMonitor) renew(ctx context.Context, t store.CanaryTrip, now time.Time) error {
	nodes, err := m.Store.GroupNodes(ctx, t.GroupID)
	if err != nil {
		return err
	}
	cmds, err := m.commands(nodes, t.Policies, now)
	if err != nil {
		return err
	}
	if _, err := m.Store.RenewCanaryTrip(ctx, t.ID, cmds, now.UTC()); err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	if m.Kick != nil {
		m.Kick.Kick()
	}
	return nil
}
