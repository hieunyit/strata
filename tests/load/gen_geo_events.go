package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

type geoPoint struct {
	Country string
	City    string
	Lat     float32
	Lon     float32
	ASN     uint32
	ASOrg   string
}

var topGeoPoints = []geoPoint{
	{Country: "VN", City: "Hanoi", Lat: 21.0285, Lon: 105.8542, ASN: 7552, ASOrg: "Viettel Group"},
	{Country: "VN", City: "Ho Chi Minh City", Lat: 10.8231, Lon: 106.6297, ASN: 45899, ASOrg: "VNPT"},
	{Country: "US", City: "Ashburn", Lat: 39.0438, Lon: -77.4874, ASN: 14618, ASOrg: "Amazon.com"},
	{Country: "US", City: "San Jose", Lat: 37.3382, Lon: -121.8863, ASN: 15169, ASOrg: "Google LLC"},
	{Country: "SG", City: "Singapore", Lat: 1.3521, Lon: 103.8198, ASN: 45102, ASOrg: "Singtel"},
	{Country: "DE", City: "Frankfurt", Lat: 50.1109, Lon: 8.6821, ASN: 3320, ASOrg: "Deutsche Telekom"},
	{Country: "JP", City: "Tokyo", Lat: 35.6762, Lon: 139.6503, ASN: 2516, ASOrg: "KDDI"},
	{Country: "GB", City: "London", Lat: 51.5074, Lon: -0.1278, ASN: 2856, ASOrg: "British Telecom"},
	{Country: "FR", City: "Paris", Lat: 48.8566, Lon: 2.3522, ASN: 3215, ASOrg: "Orange"},
	{Country: "KR", City: "Seoul", Lat: 37.5665, Lon: 126.9780, ASN: 4766, ASOrg: "Korea Telecom"},
	{Country: "AU", City: "Sydney", Lat: -33.8688, Lon: 151.2093, ASN: 1221, ASOrg: "Telstra"},
	{Country: "CA", City: "Toronto", Lat: 43.6532, Lon: -79.3832, ASN: 852, ASOrg: "Telus"},
}

var otherCountries = []string{
	"IN", "BR", "ID", "MY", "TH", "PH", "NL", "IT", "ES", "SE", "CH", "PL", "MX", "ZA", "NZ", "IE", "NO", "DK", "FI", "AT",
}

func main() {
	addr := flag.String("addr", "127.0.0.1:9000", "ClickHouse native protocol address")
	database := flag.String("database", "default", "ClickHouse database")
	user := flag.String("user", "strata", "ClickHouse user")
	password := flag.String("password", "", "ClickHouse password")
	count := flag.Int("count", 100000, "Number of events to generate")
	days := flag.Int("days", 30, "Span of days for generated events")
	benchOnly := flag.Bool("bench", false, "Only run benchmark queries without inserting data")
	batchSize := flag.Int("batch", 10000, "Batch insert size")
	flag.Parse()

	conn, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{*addr},
		Auth: clickhouse.Auth{
			Database: *database,
			Username: *user,
			Password: *password,
		},
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		log.Fatalf("connect ClickHouse: %v", err)
	}
	defer conn.Close()

	ctx := context.Background()
	if err := conn.Ping(ctx); err != nil {
		log.Fatalf("ping ClickHouse: %v", err)
	}
	fmt.Printf("Connected to ClickHouse at %s (db: %s)\n", *addr, *database)

	if !*benchOnly {
		generateData(ctx, conn, *count, *days, *batchSize)
	}

	runBenchmark(ctx, conn)
}

func generateData(ctx context.Context, conn driver.Conn, totalCount, days, batchSize int) {
	fmt.Printf("Generating %d events spread across %d days (batch size: %d)...\n", totalCount, days, batchSize)
	start := time.Now()
	now := time.Now().UTC()
	spanSec := int64(days * 86400)

	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	inserted := 0

	for inserted < totalCount {
		currentBatch := batchSize
		if inserted+currentBatch > totalCount {
			currentBatch = totalCount - inserted
		}

		batch, err := conn.PrepareBatch(ctx, `
			INSERT INTO events (
				block_id, timestamp, node_id, connector_type, policy_id, policy_version,
				client_ip, identity, request_id, http_method, http_host, http_path, status_code, action,
				score_protocol, score_sqli, score_xss, score_anomaly, matched_rules,
				received_at, country_iso, city, lat, lon, asn, as_org
			)
		`)
		if err != nil {
			log.Fatalf("prepare batch: %v", err)
		}

		for i := 0; i < currentBatch; i++ {
			eventNum := inserted + i
			offsetSec := rng.Int63n(spanSec)
			ts := now.Add(-time.Duration(offsetSec) * time.Second)

			// 30% internal, 56% top countries, 14% other countries
			r := rng.Float64()
			var country, city, asOrg string
			var lat, lon float32
			var asn uint32

			if r < 0.30 {
				country = "INTERNAL"
				city = ""
				lat = 0
				lon = 0
				asn = 0
				asOrg = ""
			} else if r < 0.86 {
				pt := topGeoPoints[rng.Intn(len(topGeoPoints))]
				country = pt.Country
				city = pt.City
				lat = pt.Lat + (rng.Float32()-0.5)*0.05
				lon = pt.Lon + (rng.Float32()-0.5)*0.05
				asn = pt.ASN
				asOrg = pt.ASOrg
			} else {
				country = otherCountries[rng.Intn(len(otherCountries))]
				city = "Capital"
				lat = 20.0 + rng.Float32()*30.0
				lon = 10.0 + rng.Float32()*90.0
				asn = uint32(10000 + rng.Intn(50000))
				asOrg = "Regional ISP"
			}

			blockID := fmt.Sprintf("STR-%04X-%04X-%04X-%04X", rng.Intn(0xFFFF), rng.Intn(0xFFFF), rng.Intn(0xFFFF), rng.Intn(0xFFFF))
			action := "log"
			status := uint16(200)
			sqliScore := int32(0)
			xssScore := int32(0)
			var rules []uint32

			if rng.Float64() < 0.25 {
				action = "block"
				status = 403
				if rng.Float64() < 0.5 {
					sqliScore = 100
					rules = []uint32{942100}
				} else {
					xssScore = 100
					rules = []uint32{941100}
				}
			}

			err := batch.Append(
				blockID,
				ts,
				fmt.Sprintf("node-%d", 1+rng.Intn(8)),
				"nginx",
				"example-api",
				uint64(1),
				fmt.Sprintf("198.51.100.%d", 1+rng.Intn(254)),
				"",
				fmt.Sprintf("req-%08x", eventNum),
				"GET",
				"api.example.test",
				fmt.Sprintf("/v1/items/%d", rng.Intn(10000)),
				status,
				action,
				int32(0),
				sqliScore,
				xssScore,
				sqliScore+xssScore,
				rules,
				ts.Add(50*time.Millisecond),
				country,
				city,
				lat,
				lon,
				asn,
				asOrg,
			)
			if err != nil {
				log.Fatalf("append row: %v", err)
			}
		}

		if err := batch.Send(); err != nil {
			log.Fatalf("send batch: %v", err)
		}
		inserted += currentBatch
		if inserted%50000 == 0 || inserted == totalCount {
			fmt.Printf("... inserted %d / %d events (%.1fs elapsed)\n", inserted, totalCount, time.Since(start).Seconds())
		}
	}
	fmt.Printf("Data generation complete: %d events in %v\n\n", totalCount, time.Since(start).Round(time.Millisecond))
}

func runBenchmark(ctx context.Context, conn driver.Conn) {
	fmt.Println("=== RUNNING W17-Q-01 SLA BENCHMARK ===")
	to := time.Now().UTC()
	from24h := to.Add(-24 * time.Hour)
	from7d := to.Add(-7 * 24 * time.Hour)
	from30d := to.Add(-30 * 24 * time.Hour)

	benchmarks := []struct {
		name       string
		query      string
		args       []any
		slaTarget  time.Duration
		stretchSLA time.Duration
	}{
		{
			name: "Top Countries Aggregation (24h)",
			query: `
				SELECT country_iso, sum(count) AS total_events, sum(blocked_count) AS blocked_events
				FROM events_geo_minute
				WHERE minute >= ? AND minute <= ? AND country_iso != 'INTERNAL' AND country_iso != ''
				GROUP BY country_iso
				ORDER BY total_events DESC
				LIMIT 50
			`,
			args:       []any{from24h, to},
			slaTarget:  1000 * time.Millisecond,
			stretchSLA: 200 * time.Millisecond,
		},
		{
			name: "Global Choropleth Summary (30d)",
			query: `
				SELECT country_iso, sum(count) AS total_events, sum(blocked_count) AS blocked_events
				FROM events_geo_minute
				WHERE minute >= ? AND minute <= ? AND country_iso != 'INTERNAL' AND country_iso != ''
				GROUP BY country_iso
				ORDER BY total_events DESC
			`,
			args:       []any{from30d, to},
			slaTarget:  3000 * time.Millisecond,
			stretchSLA: 800 * time.Millisecond,
		},
		{
			name: "City Geohash Grid (24h)",
			query: `
				SELECT geohash4, any(country_iso), any(city), avg(lat), avg(lon), sum(count), sum(blocked_count)
				FROM events_geo_grid
				WHERE window_5m >= ? AND window_5m <= ?
				GROUP BY geohash4
				ORDER BY sum(count) DESC
				LIMIT 100
			`,
			args:       []any{from24h, to},
			slaTarget:  1000 * time.Millisecond,
			stretchSLA: 300 * time.Millisecond,
		},
		{
			name: "Top ASN Timeline (7d)",
			query: `
				SELECT asn, sum(count) AS total_events, sum(blocked_count) AS blocked_events
				FROM events_geo_minute
				WHERE minute >= ? AND minute <= ? AND asn > 0
				GROUP BY asn
				ORDER BY total_events DESC
				LIMIT 50
			`,
			args:       []any{from7d, to},
			slaTarget:  2000 * time.Millisecond,
			stretchSLA: 500 * time.Millisecond,
		},
	}

	allPassed := true
	for _, bm := range benchmarks {
		// Run 5 iterations to measure average and max latency
		var totalDur time.Duration
		var maxDur time.Duration
		var rowCount int

		successIter := 0
		for iter := 0; iter < 5; iter++ {
			t0 := time.Now()
			rows, err := conn.Query(ctx, bm.query, bm.args...)
			if err != nil {
				// Materialized views may not exist yet if table is raw
				fmt.Printf("FAIL: %s: %v\n", bm.name, err)
				allPassed = false
				break
			}
			rowCount = 0
			for rows.Next() {
				rowCount++
			}
			rows.Close()
			dur := time.Since(t0)
			totalDur += dur
			if dur > maxDur {
				maxDur = dur
			}
			successIter++
		}

		if successIter == 0 {
			continue
		}
		avgDur := totalDur / time.Duration(successIter)
		status := "PASS"
		if maxDur > bm.slaTarget {
			status = "SLA BREACH"
			allPassed = false
		} else if avgDur <= bm.stretchSLA {
			status = "EXCELLENT (< Stretch SLA)"
		}

		fmt.Printf("[ %s ] %s\n", status, bm.name)
		fmt.Printf("   Rows: %d | Avg: %v | Max: %v | SLA Limit: %v (Stretch: %v)\n",
			rowCount, avgDur.Round(time.Millisecond), maxDur.Round(time.Millisecond), bm.slaTarget, bm.stretchSLA)
	}

	if allPassed {
		fmt.Println("\nAll W17-Q-01 SLA benchmarks PASSED successfully!")
	} else {
		fmt.Println("\nSome benchmarks exceeded target SLA thresholds or encountered errors.")
	}
}
