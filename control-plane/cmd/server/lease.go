package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"sync/atomic"
	"time"

	"github.com/strata/strata/control-plane/store"
)

// leaseKeeper holds the control plane lease (CP-A03): one control plane
// serves at a time, since the Fleet state lives in this process's memory.
type leaseKeeper struct {
	store *store.Store
	ttl   time.Duration
	lease store.Lease
	held  atomic.Bool
}

func leaseHolder() string {
	host, _ := os.Hostname()
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%s/%d/%s", host, os.Getpid(), hex.EncodeToString(b))
}

// acquire waits up to ttl plus a margin for a lease left by a control plane
// that stopped without releasing it, then gives up.
func (k *leaseKeeper) acquire(ctx context.Context, holder string) error {
	deadline := time.Now().Add(k.ttl + 10*time.Second)
	for {
		l, err := k.store.AcquireLease(ctx, holder, k.ttl)
		if err == nil {
			k.lease = l
			k.held.Store(true)
			log.Printf("[INFO] control plane lease held by %s (fencing %d)", l.Holder, l.Fencing)
			return nil
		}
		if !errors.Is(err, store.ErrLeaseHeld) || time.Now().After(deadline) {
			return err
		}
		// Hostnames and PIDs are namespace-local. Neither a matching PID
		// nor ESRCH here proves that another container's holder is dead.
		// Only expiry/release in PostgreSQL permits taking over the lease.
		log.Printf("[WARN] %v; waiting for it to expire", err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

// keep renews the lease every ttl/3 until ctx ends, then releases it. If the
// lease is lost, or cannot be renewed before it would expire, another
// control plane may take over: this one exits rather than serve beside it.
func (k *leaseKeeper) keep(ctx context.Context, exit func(string)) {
	t := time.NewTicker(k.ttl / 3)
	defer t.Stop()
	lastOK := time.Now()
	for {
		select {
		case <-ctx.Done():
			rctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			if err := k.store.ReleaseLease(rctx, k.lease); err != nil {
				log.Printf("[WARN] release lease: %v", err)
			}
			cancel()
			k.held.Store(false)
			return
		case <-t.C:
		}
		rctx, cancel := context.WithTimeout(ctx, k.ttl/3)
		l, err := k.store.RenewLease(rctx, k.lease, k.ttl)
		cancel()
		switch {
		case err == nil:
			k.lease, lastOK = l, time.Now()
		case errors.Is(err, store.ErrLeaseLost):
			k.held.Store(false)
			exit("control plane lease taken over by another control plane")
			return
		case ctx.Err() != nil:
			continue
		default:
			log.Printf("[WARN] renew lease: %v", err)
			if time.Since(lastOK) > k.ttl*2/3 {
				k.held.Store(false)
				exit("control plane lease could not be renewed before it expires: " + err.Error())
				return
			}
		}
	}
}
