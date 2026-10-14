// Package batch groups events from the event socket into batches and
// appends each batch to the spool, which assigns its seq.
package batch

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"

	eventv1 "github.com/strata/strata/agent/gen/strata/event/v1"
	fleetv1 "github.com/strata/strata/agent/gen/strata/fleet/v1"
)

// Appender is the part of the spool the batcher uses.
type Appender interface {
	Append(payload []byte, events uint32) (uint64, error)
}

// Options configures a batcher.
type Options struct {
	MaxEvents int           // default 500
	MaxBytes  int           // encoded size of the batch, default 1 MB
	MaxDelay  time.Duration // default 1 s
	// NodeID replaces the node id the worker put in each event.
	NodeID string
}

// Batcher is fed through Add and flushes from Run.
type Batcher struct {
	opts Options
	sp   Appender
	in   chan item
}

// item: an event or a replay sample (W12-N-01); both ride the batches.
type item struct {
	ev *eventv1.Event
	s  *eventv1.ReplaySample
}

// New returns a batcher writing to sp.
func New(sp Appender, opts Options) *Batcher {
	if opts.MaxEvents <= 0 {
		opts.MaxEvents = 500
	}
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = 1 << 20
	}
	if opts.MaxDelay <= 0 {
		opts.MaxDelay = time.Second
	}
	return &Batcher{opts: opts, sp: sp, in: make(chan item, opts.MaxEvents)}
}

// Add queues an event; it blocks while the batcher is writing to the
// spool, which leaves new datagrams in the socket buffer.
func (b *Batcher) Add(ctx context.Context, ev *eventv1.Event) {
	select {
	case b.in <- item{ev: ev}:
	case <-ctx.Done():
	}
}

// AddSample queues a replay sample like Add.
func (b *Batcher) AddSample(ctx context.Context, s *eventv1.ReplaySample) {
	select {
	case b.in <- item{s: s}:
	case <-ctx.Done():
	}
}

// Run flushes batches until ctx is done, then flushes what is pending
// and returns. A spool error stops Run.
func (b *Batcher) Run(ctx context.Context) error {
	t := time.NewTimer(b.opts.MaxDelay)
	defer t.Stop()
	var cur fleetv1.EventBatch
	size := 0
	count := func() int { return len(cur.Events) + len(cur.Samples) }
	flush := func() error {
		if count() == 0 {
			return nil
		}
		payload, err := proto.Marshal(&cur)
		if err != nil {
			return fmt.Errorf("batch: encode: %w", err)
		}
		if _, err := b.sp.Append(payload, uint32(count())); err != nil {
			return fmt.Errorf("batch: spool: %w", err)
		}
		cur.Events, cur.Samples, size = nil, nil, 0
		return nil
	}
	add := func(it item) error {
		var n int
		if it.ev != nil {
			if b.opts.NodeID != "" {
				it.ev.NodeId = b.opts.NodeID
			}
			n = proto.Size(it.ev) + 8 // field tag and length prefix
		} else {
			if b.opts.NodeID != "" {
				it.s.NodeId = []byte(b.opts.NodeID)
			}
			n = proto.Size(it.s) + 8
		}
		if size > 0 && size+n > b.opts.MaxBytes {
			if err := flush(); err != nil {
				return err
			}
		}
		if count() == 0 {
			t.Reset(b.opts.MaxDelay)
		}
		if it.ev != nil {
			cur.Events = append(cur.Events, it.ev)
		} else {
			cur.Samples = append(cur.Samples, it.s)
		}
		size += n
		if count() >= b.opts.MaxEvents {
			return flush()
		}
		return nil
	}
	for {
		select {
		case it := <-b.in:
			if err := add(it); err != nil {
				return err
			}
		case <-t.C:
			if err := flush(); err != nil {
				return err
			}
			t.Reset(b.opts.MaxDelay)
		case <-ctx.Done():
			// Drain what Add already queued.
			for {
				select {
				case it := <-b.in:
					if err := add(it); err != nil {
						return err
					}
				default:
					return flush()
				}
			}
		}
	}
}
