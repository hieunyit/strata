// Package pusher sends spooled batches on FleetService.PushEvents and
// moves the spool's ack point as EventAcks arrive (nginx-module.md ›
// "Giao thức gRPC agent ↔ control plane", Độ tin cậy).
//
// Each stream starts again from the last acked seq and resends batches
// under their original seq; the control plane drops the ones it already
// committed. Lost connections are retried with exponential backoff and
// jitter; RESOURCE_EXHAUSTED also halves the number of batches in flight.
package pusher

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"sync/atomic"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	fleetv1 "github.com/strata/strata/agent/gen/strata/fleet/v1"
	"github.com/strata/strata/agent/internal/spool"
)

// Spool is the part of spool.Spool the pusher uses.
type Spool interface {
	Read(after uint64, max int) ([]spool.Record, error)
	Ack(seq uint64) error
	Stats() spool.Stats
	Notify() <-chan struct{}
}

// Options configures a pusher.
type Options struct {
	Window     int           // most batches in flight, default 32
	BackoffMin time.Duration // default 1 s
	BackoffMax time.Duration // default 60 s
}

// Counters are read with atomic loads.
type Counters struct {
	BatchesSent  atomic.Uint64 // including resends
	Reconnects   atomic.Uint64
	Throttled    atomic.Uint64 // RESOURCE_EXHAUSTED from the control plane
	Window       atomic.Int64
	LastAckedSeq atomic.Uint64
}

// Pusher pushes the spool to the control plane.
type Pusher struct {
	client fleetv1.FleetServiceClient
	sp     Spool
	opts   Options
	C      Counters
}

// New returns a pusher.
func New(client fleetv1.FleetServiceClient, sp Spool, opts Options) *Pusher {
	if opts.Window <= 0 {
		opts.Window = 32
	}
	if opts.BackoffMin <= 0 {
		opts.BackoffMin = time.Second
	}
	if opts.BackoffMax < opts.BackoffMin {
		opts.BackoffMax = 60 * time.Second
	}
	p := &Pusher{client: client, sp: sp, opts: opts}
	p.C.Window.Store(int64(opts.Window))
	return p
}

// Run pushes until ctx is done.
func (p *Pusher) Run(ctx context.Context) error {
	backoff := p.opts.BackoffMin
	for {
		progressed, err := p.stream(ctx)
		if ctx.Err() != nil {
			return nil
		}
		if errors.Is(err, errSpool) {
			return err
		}
		if status.Code(err) == codes.ResourceExhausted {
			p.C.Throttled.Add(1)
			if w := p.C.Window.Load() / 2; w >= 1 {
				p.C.Window.Store(w)
			}
		}
		if progressed {
			backoff = p.opts.BackoffMin
		}
		p.C.Reconnects.Add(1)
		// Full jitter over [backoff/2, backoff].
		d := backoff/2 + rand.N(backoff/2+1)
		t := time.NewTimer(d)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil
		case <-t.C:
		}
		backoff = min(2*backoff, p.opts.BackoffMax)
	}
}

var errSpool = errors.New("pusher: spool")

// stream runs one PushEvents stream until it fails. It reports whether
// any ack arrived, which resets the backoff.
func (p *Pusher) stream(ctx context.Context) (progressed bool, err error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	st, err := p.client.PushEvents(ctx)
	if err != nil {
		return false, fmt.Errorf("pusher: open stream: %w", err)
	}

	acks := make(chan uint64, 64)
	recvErr := make(chan error, 1)
	go func() {
		for {
			a, err := st.Recv()
			if err != nil {
				recvErr <- err
				return
			}
			select {
			case acks <- a.GetAckedSeq():
			case <-ctx.Done():
				recvErr <- ctx.Err()
				return
			}
		}
	}()

	acked := p.sp.Stats().AckedSeq
	sent := acked // highest seq sent on this stream
	var inflight []uint64
	onAck := func(seq uint64) error {
		if seq <= acked {
			return nil
		}
		if err := p.sp.Ack(seq); err != nil {
			return fmt.Errorf("%w: ack %d: %w", errSpool, seq, err)
		}
		acked = seq
		p.C.LastAckedSeq.Store(seq)
		progressed = true
		for len(inflight) > 0 && inflight[0] <= seq {
			inflight = inflight[1:]
		}
		// Additive increase back to the configured window.
		if w := p.C.Window.Load(); w < int64(p.opts.Window) {
			p.C.Window.Store(w + 1)
		}
		return nil
	}

	for {
		if room := int(p.C.Window.Load()) - len(inflight); room > 0 {
			recs, err := p.sp.Read(sent, room)
			if err != nil {
				return progressed, fmt.Errorf("%w: %w", errSpool, err)
			}
			for _, r := range recs {
				b := &fleetv1.EventBatch{}
				if err := proto.Unmarshal(r.Payload, b); err != nil {
					return progressed, fmt.Errorf("%w: decode seq %d: %w", errSpool, r.Seq, err)
				}
				b.Seq = r.Seq
				if err := st.Send(b); err != nil {
					return progressed, fmt.Errorf("pusher: send seq %d: %w", r.Seq, recvOr(recvErr, err))
				}
				p.C.BatchesSent.Add(1)
				sent = r.Seq
				inflight = append(inflight, r.Seq)
			}
			if len(recs) > 0 {
				continue
			}
		}
		select {
		case <-ctx.Done():
			return progressed, ctx.Err()
		case <-p.sp.Notify():
		case seq := <-acks:
			if err := onAck(seq); err != nil {
				return progressed, err
			}
		case err := <-recvErr:
			return progressed, fmt.Errorf("pusher: receive ack: %w", err)
		}
	}
}

// recvOr prefers the status the server sent: Send returns io.EOF when the
// stream was ended by the server and Recv holds the real error.
func recvOr(recvErr <-chan error, sendErr error) error {
	select {
	case err := <-recvErr:
		return err
	case <-time.After(time.Second):
		return sendErr
	}
}
