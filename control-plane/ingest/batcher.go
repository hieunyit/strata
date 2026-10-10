package ingest

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

var (
	ErrBufferFull    = errors.New("event buffer is full")
	ErrBatcherClosed = errors.New("batcher is closed")
)

// BatcherConfig configures batch aggregation and flush behaviors.
type BatcherConfig struct {
	MaxBatchSize  int           // Max events per batch (e.g. 2000)
	FlushInterval time.Duration // Max time before flushing an incomplete batch (e.g. 50ms)
	BufferSize    int           // Capacity of input channel buffer (e.g. 50000)
}

// DefaultBatcherConfig returns production-tuned defaults.
func DefaultBatcherConfig() BatcherConfig {
	return BatcherConfig{
		MaxBatchSize:  2000,
		FlushInterval: 50 * time.Millisecond,
		BufferSize:    50000,
	}
}

type batchSubmission struct {
	events []Event
	done   chan error
}

// Batcher aggregates events into batches and flushes them to an EventStore.
type Batcher struct {
	cfg      BatcherConfig
	store    EventStore
	subChan  chan batchSubmission
	flushReq chan chan error
	stopChan chan struct{}
	exited   chan struct{} // closed when runLoop returns
	wg       sync.WaitGroup
	isClosed atomic.Bool

	// Metrics
	eventsReceived atomic.Uint64
	eventsFlushed  atomic.Uint64
	batchesFlushed atomic.Uint64
	flushErrors    atomic.Uint64
}

// NewBatcher starts a background batching loop.
func NewBatcher(cfg BatcherConfig, store EventStore) *Batcher {
	if cfg.MaxBatchSize <= 0 {
		cfg.MaxBatchSize = 2000
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 50 * time.Millisecond
	}
	if cfg.BufferSize <= 0 {
		cfg.BufferSize = 50000
	}

	b := &Batcher{
		cfg:      cfg,
		store:    store,
		subChan:  make(chan batchSubmission, cfg.BufferSize),
		flushReq: make(chan chan error),
		stopChan: make(chan struct{}),
		exited:   make(chan struct{}),
	}

	b.wg.Add(1)
	go b.runLoop()

	return b
}

// Submit enqueues an event for batching without waiting for persistence.
// Returns ErrBufferFull if buffer is saturated (backpressure), or ErrBatcherClosed.
func (b *Batcher) Submit(evt Event) error {
	if b.isClosed.Load() {
		return ErrBatcherClosed
	}

	select {
	case b.subChan <- batchSubmission{events: []Event{evt}}:
		b.eventsReceived.Add(1)
		return nil
	default:
		return ErrBufferFull
	}
}

// SubmitBatch enqueues multiple events for batching.
func (b *Batcher) SubmitBatch(events []Event) error {
	if b.isClosed.Load() {
		return ErrBatcherClosed
	}
	if len(events) == 0 {
		return nil
	}

	select {
	case b.subChan <- batchSubmission{events: events}:
		b.eventsReceived.Add(uint64(len(events)))
		return nil
	default:
		return ErrBufferFull
	}
}

// SubmitAndAwait enqueues events and waits until they are successfully persisted to EventStore.
// Returns error if store fails, context cancelled, buffer is full, or batcher is closed.
func (b *Batcher) SubmitAndAwait(ctx context.Context, events []Event) error {
	if b.isClosed.Load() {
		return ErrBatcherClosed
	}
	if len(events) == 0 {
		return nil
	}

	done := make(chan error, 1)
	sub := batchSubmission{
		events: events,
		done:   done,
	}

	select {
	case b.subChan <- sub:
		b.eventsReceived.Add(uint64(len(events)))
	default:
		return ErrBufferFull
	}

	select {
	case err := <-done:
		return err
	case <-b.exited:
		// The loop may have flushed us on its way out.
		select {
		case err := <-done:
			return err
		default:
			return ErrBatcherClosed
		}
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Flush synchronously flushes all currently buffered events.
func (b *Batcher) Flush(ctx context.Context) error {
	if b.isClosed.Load() {
		return nil
	}
	errChan := make(chan error, 1)
	select {
	case b.flushReq <- errChan:
		select {
		case err := <-errChan:
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Close gracefully stops the batcher and flushes remaining events.
func (b *Batcher) Close(ctx context.Context) error {
	if !b.isClosed.CompareAndSwap(false, true) {
		return nil // already closed
	}

	close(b.stopChan)

	done := make(chan struct{})
	go func() {
		b.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// runLoop is the internal aggregation loop.
func (b *Batcher) runLoop() {
	defer b.wg.Done()
	defer close(b.exited)

	ticker := time.NewTicker(b.cfg.FlushInterval)
	defer ticker.Stop()

	currentBatch := make([]Event, 0, b.cfg.MaxBatchSize)
	var currentNotifiers []chan error

	flushCurrent := func() error {
		if len(currentBatch) == 0 {
			return nil
		}
		// Write to store with a 5-second timeout
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := b.store.SaveEvents(ctx, currentBatch)
		cancel()

		// Notify waiting callers
		for _, ch := range currentNotifiers {
			select {
			case ch <- err:
			default:
			}
		}
		currentNotifiers = nil

		if err != nil {
			// Waiting callers got the error and do not ack, so the agent
			// resends the batch. Keeping it here would write it twice.
			b.flushErrors.Add(1)
			currentBatch = make([]Event, 0, b.cfg.MaxBatchSize)
			return err
		}

		b.eventsFlushed.Add(uint64(len(currentBatch)))
		b.batchesFlushed.Add(1)
		currentBatch = make([]Event, 0, b.cfg.MaxBatchSize)
		return nil
	}

	for {
		select {
		case sub := <-b.subChan:
			currentBatch = append(currentBatch, sub.events...)
			if sub.done != nil {
				currentNotifiers = append(currentNotifiers, sub.done)
			}
			if len(currentBatch) >= b.cfg.MaxBatchSize {
				_ = flushCurrent()
			}

		case <-ticker.C:
			if len(currentBatch) > 0 {
				_ = flushCurrent()
			}

		case respChan := <-b.flushReq:
			// Drain all currently available submissions in channel
			var flushErr error
			drained := true
			for drained {
				select {
				case sub := <-b.subChan:
					currentBatch = append(currentBatch, sub.events...)
					if sub.done != nil {
						currentNotifiers = append(currentNotifiers, sub.done)
					}
					if len(currentBatch) >= b.cfg.MaxBatchSize {
						if err := flushCurrent(); err != nil && flushErr == nil {
							flushErr = err
						}
					}
				default:
					drained = false
				}
			}
			if err := flushCurrent(); err != nil && flushErr == nil {
				flushErr = err
			}
			// Send response to flushReq exactly once
			respChan <- flushErr

		case <-b.stopChan:
			// Drain all remaining events from the channel before exiting
			for {
				select {
				case sub := <-b.subChan:
					currentBatch = append(currentBatch, sub.events...)
					if sub.done != nil {
						currentNotifiers = append(currentNotifiers, sub.done)
					}
					if len(currentBatch) >= b.cfg.MaxBatchSize {
						_ = flushCurrent()
					}
				default:
					_ = flushCurrent()
					return
				}
			}
		}
	}
}

// Stats returns runtime statistics of the batcher.
func (b *Batcher) Stats() (received, flushed, batches, errors uint64, queueLen int) {
	return b.eventsReceived.Load(),
		b.eventsFlushed.Load(),
		b.batchesFlushed.Load(),
		b.flushErrors.Load(),
		len(b.subChan)
}
