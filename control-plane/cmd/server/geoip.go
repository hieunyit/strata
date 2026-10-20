package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/strata/strata/control-plane/ingest"
)

func loadGeoIP(ctx context.Context, cityFile, asnFile string) (*ingest.GeoIPEnricher, error) {
	if cityFile == "" && asnFile == "" {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	reader, err := ingest.NewMMDBReader(ctx, cityFile, asnFile)
	if err != nil {
		return nil, fmt.Errorf("load configured GeoIP files: %w", err)
	}
	return ingest.NewGeoIPEnricher(reader), nil
}

// backfillGeoAggregates fills the GeoIP aggregates from the events stored
// before them, once (W17-G2-01): off the start path, since it reads every
// stored event. Rerun at the next start if it fails; it counts distinct
// events, so a partial run does no harm.
func backfillGeoAggregates(ctx context.Context, ch *ingest.ClickHouseStore, ttlDays int) {
	done, err := ch.GeoBackfillDone(ctx)
	if err != nil {
		log.Printf("[WARN] GeoIP aggregates: reading the backfill mark: %v", err)
		return
	}
	if done {
		return
	}
	days := ttlDays
	if days <= 0 {
		days = 400 // events kept as they are: about the aggregates' default 13 months
	}
	start := time.Now()
	if err := ch.BackfillGeoAggregates(ctx, time.Now().AddDate(0, 0, -days)); err != nil {
		log.Printf("[WARN] GeoIP aggregates: backfill: %v (retried at the next start)", err)
		return
	}
	log.Printf("[INFO] GeoIP aggregates: backfilled %d days of events in %s", days, time.Since(start).Round(time.Second))
}

// rollupStats keeps the hourly statistics (W20-G2-01) up to date: every 30
// seconds it recomputes the hours that received events. The first run
// fills them from every stored event; until it ends the Overview reads the
// events table.
func rollupStats(ctx context.Context, ch *ingest.ClickHouseStore) {
	first := true
	for {
		start := time.Now()
		n, err := ch.RollupStats(ctx)
		switch {
		case err != nil:
			log.Printf("[WARN] statistics rollup: %v (retried in 30 s)", err)
		case first && n > 0:
			log.Printf("[INFO] statistics rollup: %d hours computed in %s", n, time.Since(start).Round(time.Second))
		}
		first = first && err != nil
		select {
		case <-ctx.Done():
			return
		case <-time.After(30 * time.Second):
		}
	}
}
