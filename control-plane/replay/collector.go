package replay

import (
	"context"
	"github.com/strata/strata/agent/pkg/privacy"
	"google.golang.org/protobuf/proto"
	"log"
	"sync"
	"sync/atomic"
	"time"

	eventv1 "github.com/strata/strata/agent/gen/strata/event/v1"
)

// Collector gathers the samples nodes send (W12-N-01: anonymized by the
// connector, they arrive with the event batches) and writes them as sample
// files, one per policy, node and anonymization key: when a file reaches
// MaxRows, or MaxAge after its first sample. Samples are best effort: those
// not written yet are lost if the control plane stops.
type Collector struct {
	Privacy func(context.Context, string, uint64) (*privacy.Filter, error)
	Store   *Store
	MaxRows int           // 1000
	MaxAge  time.Duration // 5 min
	// Authorize returns the current anonymization key ID and policy names
	// permitted by the node's active/desired bundles. nil refuses all samples.
	Authorize              func(context.Context, string) (string, map[string]bool, error)
	MaxFiles               int
	MaxBytes, MaxNodeBytes int64

	mu        sync.Mutex
	files     map[fileKey]*pending
	bytes     int64 // includes records being written
	nodeBytes map[string]int64
	writes    chan struct{}

	Received, Written, Dropped atomic.Uint64
}

type fileKey struct{ policy, node, keyID string }

type pending struct {
	first time.Time
	recs  []Record
	bytes int64
}

// NewCollector writes to st.
func NewCollector(st *Store) *Collector {
	return &Collector{Store: st, MaxRows: 1000, MaxAge: 5 * time.Minute,
		MaxFiles: 128, MaxBytes: 64 << 20, MaxNodeBytes: 8 << 20,
		files: map[fileKey]*pending{}, nodeBytes: map[string]int64{}, writes: make(chan struct{}, 1)}
}

var canaryNames = map[eventv1.CanaryGroup]string{
	eventv1.CanaryGroup_CANARY_GROUP_ENFORCE: "enforce",
	eventv1.CanaryGroup_CANARY_GROUP_SHADOW:  "shadow",
}

// RecordOf a sample, as the Go writer would have written it.
func RecordOf(node string, s *eventv1.ReplaySample) Record {
	return Record{
		TsMs: int64(s.GetTsMs()), NodeID: node, Policy: string(s.GetPolicy()), Method: string(s.GetMethod()),
		RawURI: string(s.GetRawUri()), URI: string(s.GetUri()), Args: string(s.GetArgs()), Proto: string(s.GetProto()),
		Client: string(s.GetClient()), Headers: string(s.GetHeaders()), Body: s.GetBody(), BodyLen: int64(s.GetBodyLen()),
		BodyTruncated: s.GetBodyTruncated(), Action: string(s.GetAction()), Rules: string(s.GetRules()),
		Canary: canaryNames[s.GetCanary()],
	}
}

// Add takes the samples of one batch of node (the enrolled node id).
func (c *Collector) Add(ctx context.Context, node string, samples []*eventv1.ReplaySample) {
	c.Received.Add(uint64(len(samples)))
	if c.Authorize == nil {
		c.Dropped.Add(uint64(len(samples)))
		return
	}
	keyID, policies, err := c.Authorize(ctx, node)
	if err != nil || keyID == "" {
		c.Dropped.Add(uint64(len(samples)))
		return
	}
	now := time.Now()
	// Resolve policy settings outside the buffer mutex. Missing settings drop
	// best-effort samples rather than retaining unfiltered producer data.
	prepared := map[*eventv1.ReplaySample]Record{}
	if c.Privacy != nil {
		bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		type privacyKey struct {
			name    string
			version uint64
		}
		filters := map[privacyKey]*privacy.Filter{}
		for _, sample := range samples {
			if sample == nil || proto.Size(sample) > 8192 || !policies[string(sample.GetPolicy())] || sample.GetAnonKeyId() != keyID {
				continue
			}
			k := privacyKey{string(sample.GetPolicy()), sample.GetBundleVersion()}
			filter, known := filters[k]
			if !known {
				var err error
				filter, err = c.Privacy(bounded, k.name, k.version)
				if err != nil {
					continue
				}
				filters[k] = filter
			}
			prepared[sample] = privateRecord(RecordOf(node, sample), filter)
		}
	}
	full := map[fileKey]bool{}
	c.mu.Lock()
	for _, s := range samples {
		// Match wire limits before allocating strings or retaining byte slices.
		size := proto.Size(s)
		cost := int64(2*size + 1024)
		k := fileKey{string(s.GetPolicy()), node, s.GetAnonKeyId()}
		p := c.files[k]
		if c.Privacy != nil {
			if _, ok := prepared[s]; !ok {
				c.Dropped.Add(1)
				continue
			}
			cost = max(cost, retainedRecordBytes(prepared[s]))
		}
		if s == nil || size > 8192 || k.keyID != keyID || !policies[k.policy] ||
			cost > c.MaxBytes-c.bytes || cost > c.MaxNodeBytes-c.nodeBytes[node] ||
			(p == nil && len(c.files) >= c.MaxFiles) || (p != nil && len(p.recs) >= c.MaxRows) {
			c.Dropped.Add(1)
			continue
		}
		if p == nil {
			p = &pending{first: now}
			c.files[k] = p
		}
		record := RecordOf(node, s)
		if c.Privacy != nil {
			record = prepared[s]
		}
		p.recs = append(p.recs, record)
		p.bytes += cost
		c.bytes += cost
		c.nodeBytes[node] += cost
		if len(p.recs) >= c.MaxRows {
			full[k] = true
		}
	}
	c.mu.Unlock()
	for k := range full {
		c.flush(ctx, k)
	}
}

func (c *Collector) flush(ctx context.Context, k fileKey) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	select {
	case c.writes <- struct{}{}:
	case <-ctx.Done():
		return
	}
	defer func() { <-c.writes }()
	c.mu.Lock()
	p := c.files[k]
	delete(c.files, k)
	c.mu.Unlock()
	if p == nil || len(p.recs) == 0 {
		return
	}
	defer func() {
		c.mu.Lock()
		c.bytes -= p.bytes
		c.nodeBytes[k.node] -= p.bytes
		if c.nodeBytes[k.node] == 0 {
			delete(c.nodeBytes, k.node)
		}
		c.mu.Unlock()
	}()
	key, err := c.Store.Put(ctx, k.keyID, p.recs)
	if err != nil {
		c.Dropped.Add(uint64(len(p.recs)))
		log.Printf("[WARN] replay: %d samples of %s from %s lost: %v", len(p.recs), k.policy, k.node, err)
		return
	}
	c.Written.Add(uint64(len(p.recs)))
	log.Printf("[INFO] replay: %d samples written to %s", len(p.recs), key)
}

// Run writes the files older than MaxAge every 10 s, and every file when
// ctx ends.
func (c *Collector) Run(ctx context.Context) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			flushCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			c.FlushAll(flushCtx)
			cancel()
			return
		case <-t.C:
			c.flushOlder(ctx, time.Now().Add(-c.MaxAge))
		}
	}
}

func (c *Collector) flushOlder(ctx context.Context, before time.Time) {
	c.mu.Lock()
	var ks []fileKey
	for k, p := range c.files {
		if !p.first.After(before) {
			ks = append(ks, k)
		}
	}
	c.mu.Unlock()
	for _, k := range ks {
		c.flush(ctx, k)
	}
}

// FlushAll writes every pending file.
func (c *Collector) FlushAll(ctx context.Context) {
	c.flushOlder(ctx, time.Now().Add(time.Hour))
}
