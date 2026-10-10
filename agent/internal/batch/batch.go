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
	in   chan *eventv1.Event
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
	return &Batcher{opts: opts, sp: sp, in: make(chan *eventv1.Event, opts.MaxEvents)}
}

// Add queues an event; it blocks while the batcher is writing to the
// spool, which leaves new datagrams in the socket buffer.
func (b *Batcher) Add(ctx context.Context, ev *eventv1.Event) {
	select {
	case b.in <- ev:
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
	flush := func() error {
		if len(cur.Events) == 0 {
			return nil
		}
		payload, err := proto.Marshal(&cur)
		if err != nil {
			return fmt.Errorf("batch: encode: %w", err)
		}
		if _, err := b.sp.Append(payload, uint32(len(cur.Events))); err != nil {
			return fmt.Errorf("batch: spool: %w", err)
		}
		cur.Events, size = nil, 0
		return nil
	}
	add := func(ev *eventv1.Event) error {
		if b.opts.NodeID != "" {
			ev.NodeId = b.opts.NodeID
		}
		n := proto.Size(ev) + 8 // field tag and length prefix
		if size > 0 && size+n > b.opts.MaxBytes {
			if err := flush(); err != nil {
				return err
			}
		}
		if len(cur.Events) == 0 {
			t.Reset(b.opts.MaxDelay)
		}
		cur.Events = append(cur.Events, ev)
		size += n
		if len(cur.Events) >= b.opts.MaxEvents {
			return flush()
		}
		return nil
	}
	for {
		select {
		case ev := <-b.in:
			if err := add(ev); err != nil {
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
				case ev := <-b.in:
					if err := add(ev); err != nil {
						return err
					}
				default:
					return flush()
				}
			}
		}
	}
}
