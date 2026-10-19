package ingest

import (
	"context"
	"fmt"
)

// Upgrade the unreleased branch's non-nullable Float32 columns without deleting
// historical values. Unversioned coordinates are withheld by Get/Search, since
// the old zero defaults cannot establish that a location was actually known.
func (s *ClickHouseStore) ensureGeoIPCoordinateTypes(ctx context.Context) error {
	for _, name := range []string{"lat", "lon"} {
		var typ string
		if err := s.conn.QueryRow(ctx, "SELECT type FROM system.columns WHERE database=currentDatabase() AND table=? AND name=?", s.tableName, name).Scan(&typ); err != nil {
			return fmt.Errorf("reading GeoIP %s type: %w", name, err)
		}
		if typ == "Nullable(Float64)" {
			continue
		}
		switch typ {
		case "Float32", "Float64", "Nullable(Float32)":
		default:
			return fmt.Errorf("unsupported GeoIP %s column type %q", name, typ)
		}
		if err := s.conn.Exec(ctx, fmt.Sprintf("ALTER TABLE %s MODIFY COLUMN %s Nullable(Float64)", s.tableName, name)); err != nil {
			return fmt.Errorf("upgrading GeoIP %s type: %w", name, err)
		}
	}
	return nil
}
