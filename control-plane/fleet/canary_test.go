package fleet

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"sync"
	"testing"
	"time"

	eventv1 "github.com/strata/strata/agent/gen/strata/event/v1"
	fleetv1 "github.com/strata/strata/agent/gen/strata/fleet/v1"
	"github.com/strata/strata/control-plane/store"
)

// canaryStore is an in-memory CanaryStore.
type canaryStore struct {
	mu       sync.Mutex
	policies []string
	nodes    map[string][]string
	trips    []store.CanaryTrip
	cleared  map[int64]bool
	cmds     []store.Command
	audits   []store.Audit
	rollouts []store.Rollout
	paused   []int64
}

func (s *canaryStore) CanaryPolicies(context.Context) ([]string, error) { return s.policies, nil }
func (s *canaryStore) GroupNodes(_ context.Context, g string) ([]string, error) {
	return s.nodes[g], nil
}
func (s *canaryStore) OpenCanaryTrip(_ context.Context, t store.CanaryTrip, cmds []store.Command, a store.Audit) (store.CanaryTrip, []store.Command, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, o := range s.trips {
		if o.GroupID == t.GroupID && !s.cleared[o.ID] {
			return store.CanaryTrip{}, nil, store.ErrTripOpen
		}
	}
	t.ID = int64(len(s.trips) + 1)
	t.RenewedAt = t.TrippedAt
	s.trips = append(s.trips, t)
	s.cmds = append(s.cmds, cmds...)
	s.audits = append(s.audits, a)
	return t, cmds, nil
}
func (s *canaryStore) OpenCanaryTrips(context.Context) ([]store.CanaryTrip, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []store.CanaryTrip
	for _, t := range s.trips {
		if !s.cleared[t.ID] {
			out = append(out, t)
		}
	}
	return out, nil
}
func (s *canaryStore) RenewCanaryTrip(_ context.Context, id int64, cmds []store.Command, at time.Time) ([]store.Command, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.trips[id-1].RenewedAt = at
	s.cmds = append(s.cmds, cmds...)
	return cmds, nil
}
func (s *canaryStore) ActiveRollouts(context.Context) ([]store.Rollout, error) {
	return s.rollouts, nil
}
func (s *canaryStore) SetRolloutState(_ context.Context, id int64, to, _ string, _ []string, _ store.Audit) (store.Rollout, error) {
	s.paused = append(s.paused, id)
	return store.Rollout{ID: id, State: to}, nil
}
func (s *canaryStore) clear(id int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cleared == nil {
		s.cleared = map[int64]bool{}
	}
	s.cleared[id] = true
}
func (s *canaryStore) commands() []store.Command {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]store.Command{}, s.cmds...)
}

type kickCount struct{ n int }

func (k *kickCount) Kick() { k.n++ }

// traffic: what one node serves in one second, per group.
type traffic struct {
	req           uint64  // per group
	block, log, x float64 // shares: canary blocks, shadow logs, 5xx
	x5shadow      float64
	slow          bool // canary requests take 300 ms instead of 3 ms
	// attackers: the blocks and would-be blocks come from this many client
	// addresses, the same through every node (#74); 0: each from a client
	// of its own
	attackers int
}

// sim drives n nodes of one group sending heartbeats every 15 s (spread
// over the interval) and the monitor ticking every 5 s, on a fake clock.
type sim struct {
	t      *testing.T
	m      *CanaryMonitor
	st     *canaryStore
	now    time.Time
	nodes  []string
	counts map[string]*fleetv1.NodeCounters
	accs   map[string]*[2]acc
	next   map[string]time.Time
	rng    *rand.Rand
	ips    int // client addresses handed out
}

func newSim(t *testing.T, n int, o CanaryOptions) *sim {
	st := &canaryStore{policies: []string{"example-canary"}, nodes: map[string][]string{}, rollouts: []store.Rollout{{ID: 9, State: store.RolloutRunning}}}
	s := &sim{t: t, st: st, now: time.Date(2026, 10, 14, 8, 0, 0, 0, time.UTC), counts: map[string]*fleetv1.NodeCounters{}, accs: map[string]*[2]acc{},
		next: map[string]time.Time{}, rng: rand.New(rand.NewSource(1))}
	s.m = NewCanaryMonitor(st, &kickCount{}, o)
	s.m.Now = func() time.Time { return s.now }
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("node-%02d", i)
		s.nodes = append(s.nodes, id)
		st.nodes["edge"] = append(st.nodes["edge"], id)
		s.counts[id] = &fleetv1.NodeCounters{MetricsCreatedMs: 1, Canary: &fleetv1.CanaryCounters{Latency: make([]uint64, 9)},
			CanaryShadow: &fleetv1.CanaryCounters{Latency: make([]uint64, 9)}}
		s.next[id] = s.now.Add(time.Duration(s.rng.Intn(15000)) * time.Millisecond)
	}
	return s
}

// acc keeps the fractions of one group's counters between seconds.
type acc struct{ blocked, logged, x5 float64 }

// addGroup adds one second of traffic; returns the new blocks and logs.
func addGroup(c *fleetv1.CanaryCounters, a *acc, n uint64, blocked, logged, x5 float64, slow bool) (uint64, uint64) {
	b0, l0 := c.Blocked, c.Logged
	c.Requests += n
	a.blocked += blocked * float64(n)
	a.logged += logged * float64(n)
	a.x5 += x5 * float64(n)
	c.Blocked, c.Logged, c.UpstreamServerErrors = uint64(a.blocked), uint64(a.logged), uint64(a.x5)
	if slow {
		c.Latency[6] += n // 300 ms: the 500 ms bucket
	} else {
		c.Latency[0] += n
	}
	return c.Blocked - b0, c.Logged - l0
}

// events: the node's new blocks (canary side) and would-be blocks logged
// (shadow side) as events, to the monitor.
func (s *sim) events(node string, blocks, logs uint64, attackers int) {
	ip := func() string {
		if attackers > 0 {
			return fmt.Sprintf("203.0.113.%d", s.rng.Intn(attackers))
		}
		s.ips++
		return fmt.Sprintf("%d.%d.%d.1", 10+s.ips>>16&63, s.ips>>8&255, s.ips&255) // one /24 per client
	}
	for i := uint64(0); i < blocks; i++ {
		s.m.ObserveEvent(node, &eventv1.Event{BlockId: "STR-8F3K-Q2VD-7XNM-A1PC", Action: eventv1.Action_ACTION_BLOCK,
			ClientIp: ip(), RuleIds: []uint32{942100}, Canary: eventv1.CanaryGroup_CANARY_GROUP_ENFORCE}, s.now)
	}
	for i := uint64(0); i < logs; i++ {
		s.m.ObserveEvent(node, &eventv1.Event{BlockId: "EVT-8F3K-Q2VD-7XNM-A1PC", Action: eventv1.Action_ACTION_LOG,
			ClientIp: ip(), RuleIds: []uint32{942100}, WouldBlock: true, Canary: eventv1.CanaryGroup_CANARY_GROUP_SHADOW}, s.now)
	}
}

// run advances the clock by d, one second at a time, with tr; returns the
// time of the first trip, or zero.
func (s *sim) run(d time.Duration, tr traffic) time.Time {
	var tripped time.Time
	end := s.now.Add(d)
	tick := s.now.Add(5 * time.Second)
	for s.now.Before(end) {
		s.now = s.now.Add(time.Second)
		for _, id := range s.nodes {
			c, a := s.counts[id], s.accs[id]
			if a == nil {
				// nodes do not count in step: each starts at its own fraction
				f := func() acc { return acc{s.rng.Float64(), s.rng.Float64(), s.rng.Float64()} }
				a = &[2]acc{f(), f()}
				s.accs[id] = a
			}
			nb, _ := addGroup(c.Canary, &a[0], tr.req, tr.block, 0, tr.x, tr.slow)
			_, nl := addGroup(c.CanaryShadow, &a[1], tr.req, 0, tr.log, tr.x5shadow, false)
			s.events(id, nb, nl, tr.attackers)
			if !s.now.Before(s.next[id]) {
				s.m.Observe(id, "edge", c, s.now)
				s.next[id] = s.next[id].Add(15 * time.Second)
			}
		}
		if !s.now.Before(tick) {
			if err := s.m.Tick(context.Background()); err != nil {
				s.t.Fatal(err)
			}
			tick = tick.Add(5 * time.Second)
			if tripped.IsZero() && len(s.st.trips) > 0 {
				tripped = s.now
			}
		}
	}
	return tripped
}

// W12-G2-01 "Xong khi": a policy that blocks by mistake on a canary of 20
// nodes: the canary policy is in shadow on every node of the group in under
// a minute, the running rollout pauses.
func TestMassFalsePositiveTripsWithinAMinute(t *testing.T) {
	s := newSim(t, 20, CanaryOptions{})
	normal := traffic{req: 10, block: 0.005, log: 0.005}
	if at := s.run(20*time.Minute, normal); !at.IsZero() {
		t.Fatalf("tripped on normal traffic at %v", at)
	}
	ref := s.m.groups["edge"].ref
	if ref < 0.003 || ref > 0.007 {
		t.Fatalf("learnt would-block level %v, want about 0.5%%", ref)
	}
	// the new bundle blocks 40% of requests by mistake (and would on the
	// shadow side)
	start := s.now
	at := s.run(2*time.Minute, traffic{req: 10, block: 0.4, log: 0.4})
	if at.IsZero() {
		t.Fatal("no trip")
	}
	el := at.Sub(start)
	t.Logf("tripped %v after the bad bundle", el)
	if el >= time.Minute {
		t.Fatalf("took %v", el)
	}
	tr := s.st.trips[0]
	if tr.Reason != TripBlockRate || tr.GroupID != "edge" || len(tr.Policies) != 1 {
		t.Fatalf("trip %+v", tr)
	}
	cmds := s.st.commands()
	if len(cmds) != 20 {
		t.Fatalf("%d commands", len(cmds))
	}
	for _, c := range cmds {
		if c.Kind != store.CommandForceShadow || c.PolicyID != "example-canary" || c.DurationSeconds != 86400 {
			t.Fatalf("command %+v", c)
		}
	}
	if len(s.st.paused) != 1 || s.st.paused[0] != 9 {
		t.Fatalf("rollouts paused %v", s.st.paused)
	}
	if a := s.st.audits[0]; a.Actor != monitorActor || a.Resource != "groups/edge:canaryFallback" {
		t.Fatalf("audit %+v", a)
	}
	if s.m.Trips()[TripBlockRate] != 1 {
		t.Fatalf("trips %v", s.m.Trips())
	}

	// held: no second trip, renewed every 12 h (24 h commands)
	s.run(time.Hour, normal)
	if len(s.st.trips) != 1 || len(s.st.commands()) != 20 {
		t.Fatalf("held: %d trips, %d commands", len(s.st.trips), len(s.st.commands()))
	}
	s.now = s.now.Add(11 * time.Hour)
	s.run(10*time.Second, normal)
	if len(s.st.commands()) != 40 {
		t.Fatalf("not renewed after 12 h: %d commands", len(s.st.commands()))
	}

	// cleared (clearForceShadow): watched again, the old window forgotten
	s.st.clear(tr.ID)
	if s.run(5*time.Minute, normal); len(s.st.trips) != 1 {
		t.Fatalf("tripped again after the clear: %d trips", len(s.st.trips))
	}
	s.run(time.Minute, traffic{req: 10, block: 0.4, log: 0.4})
	if len(s.st.trips) != 2 {
		t.Fatalf("not watched after the clear: %d trips", len(s.st.trips))
	}
}

// Upstream 5xx and latency: the canary against its shadow group, not
// absolute numbers.
func TestUpstreamErrorsAndLatencyCompareTheGroups(t *testing.T) {
	cases := []struct {
		name string
		tr   traffic
		want string
	}{
		{"5xx on both sides", traffic{req: 10, x: 0.05, x5shadow: 0.05}, ""},
		{"5xx 0.5 point over", traffic{req: 10, x: 0.01, x5shadow: 0.005}, ""},
		{"5xx on the canary", traffic{req: 10, x: 0.03, x5shadow: 0.005}, Trip5xx},
		{"canary slow", traffic{req: 10, slow: true}, TripLatency},
		{"normal", traffic{req: 10, block: 0.005, log: 0.005}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := newSim(t, 10, CanaryOptions{})
			s.run(2*time.Minute, c.tr)
			got := ""
			if len(s.st.trips) > 0 {
				got = s.st.trips[0].Reason
			}
			if got != c.want {
				t.Fatalf("trip %q, want %q", got, c.want)
			}
		})
	}
}

// Too few requests: nothing judged or learnt; a reload (new metrics file)
// starts the counters again without a jump.
func TestQuietGroupsAndReloads(t *testing.T) {
	s := newSim(t, 2, CanaryOptions{})
	s.run(5*time.Minute, traffic{req: 1, block: 1, log: 1}) // 2 nodes x 1/s: 120 per window, under 200
	if len(s.st.trips) != 0 || s.m.groups["edge"].learnt != 0 {
		t.Fatalf("judged a quiet group: %d trips, %d learnt", len(s.st.trips), s.m.groups["edge"].learnt)
	}

	s = newSim(t, 10, CanaryOptions{})
	s.run(10*time.Minute, traffic{req: 10, block: 0.005, log: 0.005})
	// NGINX reloads on every node: counters back to small values
	for _, id := range s.nodes {
		s.counts[id] = &fleetv1.NodeCounters{MetricsCreatedMs: 2, Canary: &fleetv1.CanaryCounters{Latency: make([]uint64, 9)},
			CanaryShadow: &fleetv1.CanaryCounters{Latency: make([]uint64, 9)}}
		delete(s.accs, id)
	}
	s.run(5*time.Minute, traffic{req: 10, block: 0.005, log: 0.005})
	if len(s.st.trips) != 0 {
		t.Fatalf("tripped on a reload: %+v", s.st.trips)
	}
	// a node without canary counters (older module) is ignored
	s.m.Observe("node-old", "edge", &fleetv1.NodeCounters{Requests: 5}, s.now)
	if _, ok := s.m.nodes["node-old"]; ok {
		t.Fatal("older module observed")
	}
}

// The block level needs the warmup before it may trip.
func TestBlockTripNeedsWarmup(t *testing.T) {
	s := newSim(t, 10, CanaryOptions{})
	s.run(2*time.Minute, traffic{req: 10, block: 0.4, log: 0.4})
	if len(s.st.trips) != 0 {
		t.Fatalf("a new canary tripped on blocks without a learnt level: %+v", s.st.trips[0])
	}
}

// regStore puts the monitor's commands where the dispatcher of the test
// server reads them.
type regStore struct {
	*canaryStore
	reg *memRegistry
}

func (r regStore) OpenCanaryTrip(ctx context.Context, t store.CanaryTrip, cmds []store.Command, a store.Audit) (store.CanaryTrip, []store.Command, error) {
	tr, out, err := r.canaryStore.OpenCanaryTrip(ctx, t, cmds, a)
	if err == nil {
		r.reg.mu.Lock()
		for _, c := range out {
			c.State = store.CommandPending
			r.reg.commands = append(r.reg.commands, c)
		}
		r.reg.mu.Unlock()
	}
	return tr, out, err
}

// W12-G2-01 through the FleetService: the group of a node comes from its
// enrollment, heartbeats feed the monitor, and the trip's ForceShadow
// reaches every connected node of the group.
func TestHeartbeatsTripAndForceShadowReachesTheNodes(t *testing.T) {
	e := newEnrollEnv(t)
	cs := &canaryStore{policies: []string{"example-canary"}, nodes: map[string][]string{}}
	mon := NewCanaryMonitor(regStore{cs, e.reg}, nil, CanaryOptions{Warmup: 1, MinRequests: 50})
	e.srv = NewServer(Config{Ingest: nopIngest{}, Registry: e.reg, CA: e.p.nodeCA(t), TrustBundle: []byte("trust"),
		BundlePubKey: []byte("bundle-pub"), Presence: NewPresence(), Canary: mon})
	e.addr = serveServer(t, e.p, e.srv)

	var streams []fleetv1.FleetService_ConnectClient
	var clients []fleetv1.FleetServiceClient
	for i := 0; i < 3; i++ {
		tok := fmt.Sprintf("tok-%d", i)
		e.reg.addToken(tok, time.Hour)
		r, pair, err := e.enroll(t, tok)
		if err != nil {
			t.Fatal(err)
		}
		cs.nodes["lab"] = append(cs.nodes["lab"], r.GetNodeId())
		cl := dial(t, e.p, e.addr, &pair)
		st, cancel := connect(t, cl, true)
		t.Cleanup(cancel)
		streams = append(streams, st)
		clients = append(clients, cl)
	}
	// each node sends n blocks of the canary side, from addrs addresses
	seq := uint64(0)
	blocks := func(n, addrs int) {
		seq++
		for _, cl := range clients {
			var evs []*eventv1.Event
			for i := 0; i < n; i++ {
				ev := event("STR-8F3K-Q2VD-7XNM-A1PC")
				ev.ClientIp = fmt.Sprintf("10.%d.0.1", i%addrs) // one /24 each
				ev.Canary = eventv1.CanaryGroup_CANARY_GROUP_ENFORCE
				evs = append(evs, ev)
			}
			if _, err := push(t, cl, &fleetv1.EventBatch{Seq: seq, Events: evs}); err != nil {
				t.Fatal(err)
			}
		}
	}
	heartbeat := func(n uint64, blocked, logged uint64) {
		for _, st := range streams {
			lat := []uint64{n, 0, 0, 0, 0, 0, 0, 0, 0}
			if err := st.Send(&fleetv1.AgentMessage{Msg: &fleetv1.AgentMessage_Heartbeat{Heartbeat: &fleetv1.Heartbeat{
				Counters: &fleetv1.NodeCounters{MetricsCreatedMs: 7,
					Canary:       &fleetv1.CanaryCounters{Requests: n, Blocked: blocked, Latency: lat},
					CanaryShadow: &fleetv1.CanaryCounters{Requests: n, Logged: logged, Latency: lat}},
			}}}); err != nil {
				t.Fatal(err)
			}
		}
	}
	nodesSeen := func() int {
		mon.mu.Lock()
		defer mon.mu.Unlock()
		return len(mon.nodes)
	}
	heartbeat(0, 0, 0)
	eventually(t, "first heartbeats", func() bool { return nodesSeen() == 3 })
	heartbeat(100, 0, 0) // learnt: nothing would block
	time.Sleep(100 * time.Millisecond)
	if err := mon.Tick(t.Context()); err != nil || len(cs.trips) != 0 {
		t.Fatalf("normal: %v %+v", err, cs.trips)
	}
	// #74: 60% of the canary blocked, every block from one address (a
	// flood through every node): counted 3 times in all, no trip
	heartbeat(200, 60, 60)
	blocks(60, 1)
	time.Sleep(100 * time.Millisecond)
	if err := mon.Tick(t.Context()); err != nil || len(cs.trips) != 0 {
		t.Fatalf("flood from one address: %v %+v", err, cs.trips)
	}
	start := time.Now()
	heartbeat(300, 120, 120) // 60% of the canary blocked, from 60 addresses
	blocks(60, 60)
	time.Sleep(100 * time.Millisecond)
	if err := mon.Tick(t.Context()); err != nil || len(cs.trips) != 1 || cs.trips[0].GroupID != "lab" {
		t.Fatalf("bad bundle: %v %+v", err, cs.trips)
	}
	if err := NewCommands(e.reg, e.srv.Presence()).Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	for i, st := range streams {
		m, err := st.Recv()
		if err != nil {
			t.Fatal(err)
		}
		fs := m.GetCommand().GetForceShadow()
		if fs.GetPolicyId() != "example-canary" || fs.GetDurationSeconds() != 86400 {
			t.Fatalf("node %d got %v", i, m)
		}
	}
	t.Logf("every node had its ForceShadow %v after the bad heartbeat", time.Since(start).Round(time.Millisecond))
}

// #74: a few clients sending a flood of blocked payloads through every
// node of the group count 3 blocks each per window: no trip, and the
// learnt level does not rise. The same share of blocks from many clients
// (a policy blocking real users) still trips.
func TestFloodFromFewSourcesDoesNotTrip(t *testing.T) {
	s := newSim(t, 20, CanaryOptions{})
	normal := traffic{req: 10, block: 0.005, log: 0.005}
	s.run(20*time.Minute, normal)
	ref := s.m.groups["edge"].ref
	for _, n := range []int{1, 5, 20} {
		// 40% of the canary's requests blocked, from n addresses
		if at := s.run(10*time.Minute, traffic{req: 10, block: 0.4, log: 0.005, attackers: n}); !at.IsZero() {
			t.Fatalf("a flood from %d addresses tripped at %v", n, at)
		}
	}
	if got := s.m.groups["edge"].ref; got > 2*ref {
		t.Fatalf("learnt level rose from %v to %v", ref, got)
	}
	if at := s.run(2*time.Minute, traffic{req: 10, block: 0.4, log: 0.4}); at.IsZero() {
		t.Fatal("blocks from many clients did not trip after the flood")
	}
}

// #74: at low traffic the Poisson test keeps chance from tripping (a
// fixed ratio on a few expected blocks would).
func TestLowTrafficDoesNotTripByChance(t *testing.T) {
	s := newSim(t, 2, CanaryOptions{})
	if at := s.run(24*time.Hour, traffic{req: 2, block: 0.01, log: 0.01}); !at.IsZero() {
		t.Fatalf("tripped by chance at %v", at)
	}
}

func TestConfigurableCanaryThresholds(t *testing.T) {
	o := (CanaryOptions{}).withDefaults()
	if err := o.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*CanaryOptions){func(o *CanaryOptions) { o.BlockFactor = math.NaN() }, func(o *CanaryOptions) { o.ErrorFactor = 1 }, func(o *CanaryOptions) { o.LatencyDelta = 0 }, func(o *CanaryOptions) { o.MinRequests = 1 }} {
		bad := o
		mutate(&bad)
		if bad.Validate() == nil {
			t.Fatal("invalid threshold accepted")
		}
	}
	m := &CanaryMonitor{o: o}
	c, s := groupCounts{req: 1000, x5: 40}, groupCounts{req: 1000, x5: 10}
	if verdict := m.judge(&groupState{}, c, s, 0, 0, false); verdict.reason != Trip5xx {
		t.Fatal("default 5xx threshold did not trip")
	}
	m.o.ErrorDelta = .05
	if verdict := m.judge(&groupState{}, c, s, 0, 0, false); verdict.reason != "" {
		t.Fatal("configured 5xx threshold ignored")
	}
}
