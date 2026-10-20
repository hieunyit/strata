package fleet

import (
	"context"
	"log"
	"sync"
	"time"

	eventv1 "github.com/strata/strata/agent/gen/strata/event/v1"
	fleetv1 "github.com/strata/strata/agent/gen/strata/fleet/v1"
	"github.com/strata/strata/control-plane/ingest"
)

// PolicyRequestsSink stores per-policy request counts (RV-N-01):
// ingest.ClickHouseStore, or the in-memory store.
type PolicyRequestsSink interface {
	SavePolicyRequests(ctx context.Context, rows []ingest.PolicyRequests) error
	// W20-F-01: the engine time of each node over each interval
	SaveEngineTime(ctx context.Context, rows []ingest.EngineTime) error
}

// MaxPendingPolicyRows bounds what waits for the store (it is failing):
// older rows are dropped first.
const MaxPendingPolicyRows = 100_000

type nodePolicies struct {
	started uint64
	counts  map[string]*eventv1.PolicyCount
}

// PolicyRequestsRecorder turns the per-policy sums of the heartbeats (since
// each agent started) into rows per interval and writes them in batches,
// so that ClickHouse does not take one small insert per heartbeat.
type PolicyRequestsRecorder struct {
	Sink     PolicyRequestsSink
	Interval time.Duration // between two writes, 10 s

	mu      sync.Mutex
	last    map[string]nodePolicies
	pending []ingest.PolicyRequests
	dropped uint64
	// W20-F-01: per node, the engine time sums of its last heartbeat
	lastEngine    map[string]nodeEngine
	pendingEngine []ingest.EngineTime
}

type nodeEngine struct {
	created uint64
	buckets []uint64
	nanos   uint64
}

// NewPolicyRequestsRecorder writes to sink; call Run.
func NewPolicyRequestsRecorder(sink PolicyRequestsSink) *PolicyRequestsRecorder {
	return &PolicyRequestsRecorder{Sink: sink, Interval: 10 * time.Second, last: map[string]nodePolicies{}, lastEngine: map[string]nodeEngine{}}
}

// Observe takes a heartbeat's counters. The first heartbeat of a node this
// control plane sees only sets its starting point (what came before is
// unknown); after an agent restart (another agent_started_ms) the sums are
// new.
func (r *PolicyRequestsRecorder) Observe(node string, nc *fleetv1.NodeCounters, at time.Time) {
	r.observeEngine(node, nc, at)
	ps := nc.GetPolicies()
	if len(ps) == 0 {
		return // a module or an agent before RV-N-01
	}
	cur := nodePolicies{started: nc.GetAgentStartedMs(), counts: make(map[string]*eventv1.PolicyCount, len(ps))}
	for _, p := range ps {
		cur.counts[p.GetPolicy()] = p
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	prev, seen := r.last[node]
	r.last[node] = cur
	if !seen {
		return
	}
	restarted := prev.started != cur.started
	for name, p := range cur.counts {
		d := ingest.PolicyRequests{Time: at.UTC(), NodeID: node, PolicyID: name, Requests: p.GetRequests(),
			Partial: p.GetPartial(), BodySkipped: p.GetBodySkipped(), Error: p.GetError(), Degraded: p.GetDegraded()}
		if o, ok := prev.counts[name]; ok && !restarted {
			if p.GetRequests() < o.GetRequests() {
				continue // sums went down without a restart: wait for the next one
			}
			d.Requests -= o.GetRequests()
			d.Partial = sub(d.Partial, o.GetPartial())
			d.BodySkipped = sub(d.BodySkipped, o.GetBodySkipped())
			d.Error = sub(d.Error, o.GetError())
			d.Degraded = sub(d.Degraded, o.GetDegraded())
		}
		if d.Requests > 0 {
			r.pending = append(r.pending, d)
		}
	}
	if over := len(r.pending) - MaxPendingPolicyRows; over > 0 {
		r.pending = append(r.pending[:0], r.pending[over:]...)
		r.dropped += uint64(over)
	}
}

func sub(a, b uint64) uint64 {
	if a < b {
		return 0
	}
	return a - b
}

// Forget drops a node (revoked).
func (r *PolicyRequestsRecorder) Forget(node string) {
	r.mu.Lock()
	delete(r.last, node)
	delete(r.lastEngine, node)
	r.mu.Unlock()
}

// Flush writes what is pending; on an error the rows stay for the next try.
func (r *PolicyRequestsRecorder) Flush(ctx context.Context) error {
	r.mu.Lock()
	rows, engine := r.pending, r.pendingEngine
	r.pending, r.pendingEngine = nil, nil
	r.mu.Unlock()
	if len(engine) > 0 {
		if err := r.Sink.SaveEngineTime(ctx, engine); err != nil {
			r.mu.Lock()
			r.pendingEngine = append(engine, r.pendingEngine...)
			r.pending = append(rows, r.pending...)
			r.mu.Unlock()
			return err
		}
	}
	if len(rows) == 0 {
		return nil
	}
	if err := r.Sink.SavePolicyRequests(ctx, rows); err != nil {
		r.mu.Lock()
		r.pending = append(rows, r.pending...)
		r.mu.Unlock()
		return err
	}
	return nil
}

// Run flushes every Interval until ctx ends, then once more.
func (r *PolicyRequestsRecorder) Run(ctx context.Context) {
	t := time.NewTicker(r.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			fctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			if err := r.Flush(fctx); err != nil {
				log.Printf("[WARN] fleet: policy requests: last flush: %v", err)
			}
			cancel()
			return
		case <-t.C:
			if err := r.Flush(ctx); err != nil && ctx.Err() == nil {
				log.Printf("[WARN] fleet: policy requests: %v", err)
			}
		}
	}
}

// observeEngine turns the engine time sums of a heartbeat (since NGINX
// made its metrics file, metrics_created_ms) into the increase since the
// node's previous one (W20-F-01). A reload starts the sums again.
func (r *PolicyRequestsRecorder) observeEngine(node string, nc *fleetv1.NodeCounters, at time.Time) {
	b := nc.GetEngineTime()
	if len(b) == 0 {
		return // an agent before W20-F-01
	}
	cur := nodeEngine{created: nc.GetMetricsCreatedMs(), buckets: append([]uint64(nil), b...), nanos: nc.GetEngineNs()}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.lastEngine == nil {
		r.lastEngine = map[string]nodeEngine{}
	}
	prev, seen := r.lastEngine[node]
	r.lastEngine[node] = cur
	if !seen {
		return
	}
	row := ingest.EngineTime{Time: at.UTC(), NodeID: node, Buckets: cur.buckets, Nanos: cur.nanos}
	if prev.created == cur.created && len(prev.buckets) == len(cur.buckets) {
		d := make([]uint64, len(cur.buckets))
		var n uint64
		for i := range d {
			if cur.buckets[i] < prev.buckets[i] {
				return // sums went down without a reload: wait for the next one
			}
			d[i] = cur.buckets[i] - prev.buckets[i]
			n += d[i]
		}
		if n == 0 {
			return
		}
		row.Buckets, row.Nanos = d, sub(cur.nanos, prev.nanos)
	}
	r.pendingEngine = append(r.pendingEngine, row)
	if over := len(r.pendingEngine) - MaxPendingPolicyRows; over > 0 {
		r.pendingEngine = append(r.pendingEngine[:0], r.pendingEngine[over:]...)
		r.dropped += uint64(over)
	}
}
