package main

import (
	"context"
	"fmt"
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
