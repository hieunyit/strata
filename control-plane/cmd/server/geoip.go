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
