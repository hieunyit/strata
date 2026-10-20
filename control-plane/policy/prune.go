package policy

import (
	"context"
	"log"
	"slices"
	"strconv"
	"strings"
	"time"
)

// KeptBundles is the part of store.Store the pruner asks which bundles
// stay (store.Store.KeptBundles).
type KeptBundles interface {
	KeptBundles(ctx context.Context, newest int) (map[uint64]bool, uint64, error)
}

// Pruner removes artifacts nothing needs any more (CP-A07): bundles out of
// the kept list the database gives (never by file age), and replay sample
// files of days past the retention. Bundles above the newest recorded
// version are uploads not recorded yet and stay.
type Pruner struct {
	Store   KeptBundles
	Objects ObjectStore
	// KeepBundles newest bundles stay besides those in use; < 1: bundles
	// are not pruned.
	KeepBundles int
	// SampleDays of replay samples stay (the day of a key's path, UTC);
	// < 1: samples are not pruned.
	SampleDays int
	Now        func() time.Time
}

// Pruned counts what one run removed.
type Pruned struct{ Bundles, Samples int }

// Prune runs once.
func (p *Pruner) Prune(ctx context.Context) (Pruned, error) {
	var out Pruned
	if p.KeepBundles > 0 {
		keep, newest, err := p.Store.KeptBundles(ctx, p.KeepBundles)
		if err != nil {
			return out, err
		}
		objs, err := p.Objects.List(ctx, "bundles/")
		if err != nil {
			return out, err
		}
		for _, o := range objs {
			seg, _, _ := strings.Cut(strings.TrimPrefix(o.Key, "bundles/"), "/")
			v, err := strconv.ParseUint(seg, 10, 64)
			if err != nil || len(seg) != 20 || v >= newest || keep[v] {
				continue // not a bundle key, or newer than the kept set covers, or kept
			}
			if err := p.Objects.Delete(ctx, o.Key); err != nil {
				return out, err
			}
			out.Bundles++
		}
	}
	if p.SampleDays > 0 {
		now := time.Now
		if p.Now != nil {
			now = p.Now
		}
		cut := now().UTC().AddDate(0, 0, -p.SampleDays)
		oldest := time.Date(cut.Year(), cut.Month(), cut.Day(), 0, 0, 0, 0, time.UTC)
		objs, err := p.Objects.List(ctx, "replay/v1/")
		if err != nil {
			return out, err
		}
		for _, o := range objs {
			// replay/v1/<policy>/yyyy/mm/dd/<file>
			parts := strings.Split(o.Key, "/")
			if len(parts) != 7 {
				continue
			}
			day, err := time.Parse("2006/01/02", strings.Join(parts[3:6], "/"))
			if err != nil || !day.Before(oldest) {
				continue
			}
			if err := p.Objects.Delete(ctx, o.Key); err != nil {
				return out, err
			}
			out.Samples++
		}
	}
	return out, nil
}

// Run prunes now and then every interval until ctx ends.
func (p *Pruner) Run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		n, err := p.Prune(ctx)
		switch {
		case err != nil:
			log.Printf("[ERROR] artifacts: pruning: %v", err)
		case n.Bundles+n.Samples > 0:
			log.Printf("[INFO] artifacts: removed %d bundles, %d replay sample files", n.Bundles, n.Samples)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// PruneGeoIP returns the GeoIPUpdater's PruneOld for objects: it removes
// geoip/<version>/… of every version not in keep; the pointer stays.
func PruneGeoIP(objects ObjectStore) func(ctx context.Context, keep []string) error {
	return func(ctx context.Context, keep []string) error {
		objs, err := objects.List(ctx, "geoip/")
		if err != nil {
			return err
		}
		for _, o := range objs {
			v, _, ok := strings.Cut(strings.TrimPrefix(o.Key, "geoip/"), "/")
			if !ok || v == "" || slices.Contains(keep, v) {
				continue // the pointer, or a version kept
			}
			if err := objects.Delete(ctx, o.Key); err != nil {
				return err
			}
		}
		return nil
	}
}
