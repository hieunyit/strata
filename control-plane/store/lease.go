package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// ErrLeaseHeld: another control plane holds the lease and it has not
// expired.
var ErrLeaseHeld = errors.New("store: another control plane holds the lease")

// ErrLeaseLost: the lease was taken over (it expired before renewal).
var ErrLeaseLost = errors.New("store: control plane lease lost")

// Lease is the control plane lease (CP-A03): one control plane serves at a
// time. Times come from PostgreSQL, not from the hosts' clocks.
type Lease struct {
	Holder    string
	Fencing   int64
	ExpiresAt time.Time
}

// AcquireLease takes the lease for holder when it is free, expired or
// already holder's; otherwise ErrLeaseHeld with the current holder.
func (s *Store) AcquireLease(ctx context.Context, holder string, ttl time.Duration) (Lease, error) {
	if holder == "" || ttl <= 0 {
		return Lease{}, errors.New("store: lease needs a holder and a ttl")
	}
	var l Lease
	err := s.pool.QueryRow(ctx, `INSERT INTO control_plane_lease (id, holder, fencing, renewed_at, expires_at)
		VALUES (1, $1, 1, now(), now() + $2::interval)
		ON CONFLICT (id) DO UPDATE SET holder = excluded.holder, renewed_at = now(), expires_at = excluded.expires_at,
			fencing = CASE WHEN control_plane_lease.holder = excluded.holder THEN control_plane_lease.fencing
			               ELSE control_plane_lease.fencing + 1 END
		WHERE control_plane_lease.expires_at < now() OR control_plane_lease.holder = excluded.holder
		RETURNING holder, fencing, expires_at`, holder, ttl.String()).Scan(&l.Holder, &l.Fencing, &l.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		cur, err := s.CurrentLease(ctx)
		if err != nil {
			return Lease{}, err
		}
		return cur, fmt.Errorf("%w: %s until %s", ErrLeaseHeld, cur.Holder, cur.ExpiresAt.UTC().Format(time.RFC3339))
	}
	if err != nil {
		return Lease{}, fmt.Errorf("store: acquire lease: %w", err)
	}
	return l, nil
}

// RenewLease extends a lease held with fencing; ErrLeaseLost when another
// control plane took it.
func (s *Store) RenewLease(ctx context.Context, l Lease, ttl time.Duration) (Lease, error) {
	err := s.pool.QueryRow(ctx, `UPDATE control_plane_lease SET renewed_at = now(), expires_at = now() + $3::interval
		WHERE id = 1 AND holder = $1 AND fencing = $2 RETURNING expires_at`, l.Holder, l.Fencing, ttl.String()).Scan(&l.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Lease{}, ErrLeaseLost
	}
	if err != nil {
		return Lease{}, fmt.Errorf("store: renew lease: %w", err)
	}
	return l, nil
}

// ReleaseLease ends a lease at once (clean shutdown), if still held.
func (s *Store) ReleaseLease(ctx context.Context, l Lease) error {
	if _, err := s.pool.Exec(ctx, `UPDATE control_plane_lease SET expires_at = now() WHERE id = 1 AND holder = $1 AND fencing = $2`,
		l.Holder, l.Fencing); err != nil {
		return fmt.Errorf("store: release lease: %w", err)
	}
	return nil
}

// CurrentLease returns the lease row; ErrNotFound when none was taken.
func (s *Store) CurrentLease(ctx context.Context) (Lease, error) {
	var l Lease
	err := s.pool.QueryRow(ctx, `SELECT holder, fencing, expires_at FROM control_plane_lease WHERE id = 1`).Scan(&l.Holder, &l.Fencing, &l.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Lease{}, ErrNotFound
	}
	if err != nil {
		return Lease{}, fmt.Errorf("store: lease: %w", err)
	}
	return l, nil
}
