package replay

import (
	"context"
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
	Store   *Store
	MaxRows int           // 1000
	MaxAge  time.Duration // 5 min

	mu    sync.Mutex
	files map[fileKey]*pending

	Received, Written, Dropped atomic.Uint64
}

type fileKey struct{ policy, node, keyID string }

type pending struct {
	first time.Time
	recs  []Record
}

// NewCollector writes to st.
func NewCollector(st *Store) *Collector {
	return &Collector{Store: st, MaxRows: 1000, MaxAge: 5 * time.Minute, files: map[fileKey]*pending{}}
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
	now := time.Now()
	var full []fileKey
	c.mu.Lock()
	for _, s := range samples {
		c.Received.Add(1)
		k := fileKey{string(s.GetPolicy()), node, s.GetAnonKeyId()}
		p := c.files[k]
		if p == nil {
			p = &pending{first: now}
			c.files[k] = p
		}
		p.recs = append(p.recs, RecordOf(node, s))
		if len(p.recs) >= c.MaxRows {
			full = append(full, k)
		}
	}
	c.mu.Unlock()
	for _, k := range full {
		c.flush(ctx, k)
	}
}

func (c *Collector) flush(ctx context.Context, k fileKey) {
	c.mu.Lock()
	p := c.files[k]
	delete(c.files, k)
	c.mu.Unlock()
	if p == nil || len(p.recs) == 0 {
		return
	}
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
			c.FlushAll(context.Background())
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
