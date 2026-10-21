package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/strata/strata/control-plane/config"
	"github.com/strata/strata/control-plane/db"
	"github.com/strata/strata/control-plane/health"
	"github.com/strata/strata/control-plane/ingest"
	"github.com/strata/strata/control-plane/store"
)

// doctor is read-only: it checks existing schemas and never migrates or starts
// workers. It does not collect raw logs or copy credential/configuration files.
func doctorCommand(args []string) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	path := fs.String("config", os.Getenv("STRATA_CONFIG"), "Control plane YAML configuration")
	bundle := fs.String("support-bundle", "", "Private support archive to create (must not exist)")
	asJSON := fs.Bool("json", false, "Print machine-readable observations")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return 1
	}
	if *path != "" {
		file, err := config.Load(*path)
		if err != nil {
			fmt.Fprintln(os.Stderr, "doctor: configuration could not be loaded")
			return 1
		}
		if _, err = file.Apply(flag.CommandLine, nil); err != nil {
			fmt.Fprintln(os.Stderr, "doctor: configuration could not be applied")
			return 1
		}
	}
	value := func(name string) string {
		if fl := flag.CommandLine.Lookup(name); fl != nil {
			return fl.Value.String()
		}
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var pg *store.Store
	var pool *pgxpool.Pool
	if dsn := os.Getenv("STRATA_POSTGRES_DSN"); dsn != "" {
		p, err := pgxpool.New(ctx, dsn)
		if err == nil {
			pool = p
			defer pool.Close()
			pg = store.New(pool)
		}
	}
	var events ingest.EventStore
	var clickhouse *ingest.ClickHouseStore
	if value("in-memory") != "true" {
		ch, err := ingest.OpenClickHouseStore(ingest.ClickHouseConfig{Addr: value("clickhouse-addr"), Database: "default", Username: value("clickhouse-user"), Password: os.Getenv("STRATA_CLICKHOUSE_PASSWORD")})
		if err == nil {
			clickhouse = ch
			events = ch
			defer ch.Close()
		}
	}
	service := health.Service{Store: pg, Events: events, Version: version}
	service.Ready = func(ctx context.Context) (map[string]string, bool) {
		parts := map[string]string{"postgres": "disabled", "clickhouse": "disabled", "lease": "disabled"}
		if pool != nil {
			parts["postgres"] = "error"
			if pool.Ping(ctx) == nil {
				got, err := db.Version(ctx, pool)
				latest, lerr := db.Latest()
				if err == nil && lerr == nil && got == latest {
					parts["postgres"] = "ok"
				}
			}
			if value("single-control-plane") == "true" {
				var held bool
				err := pool.QueryRow(ctx, "SELECT expires_at>now() FROM control_plane_lease WHERE id=1").Scan(&held)
				if err == nil && held {
					parts["lease"] = "held"
				} else if err == nil || errors.Is(err, pgx.ErrNoRows) {
					parts["lease"] = "expired"
				} else {
					parts["lease"] = "error"
				}
			}
		}
		if clickhouse != nil {
			parts["clickhouse"] = "degraded"
			v, err := clickhouse.ReadCHSchemaVersion(ctx)
			if err == nil && v == ingest.LatestCHMigration() {
				parts["clickhouse"] = "ok"
			}
		}
		return parts, parts["postgres"] == "ok"
	}
	if objects := value("objects-dir"); objects != "" {
		service.FreeBytes = func() (uint64, error) { return diskFree(objects) }
	}
	snapshot := service.Collect(ctx, nil)
	if *asJSON {
		if err := json.NewEncoder(os.Stdout).Encode(snapshot); err != nil {
			return 1
		}
	} else {
		for _, c := range snapshot.Checks {
			v := ""
			if c.Value != nil {
				v = *c.Value
			}
			fmt.Printf("%-22s %-12s %s  %s\n", c.ID, c.State, v, health.NextStep(c.ID))
		}
		for _, n := range snapshot.Nodes {
			for _, c := range n.Checks {
				fmt.Printf("node %-20s %-16s %s  %s\n", n.ID, c.ID, c.State, health.NextStep(c.ID))
			}
		}
		fmt.Println("Advice: restore unavailable dependencies; free artifact disk space; reconnect stale nodes; inspect spool delivery and certificate renewal. Unknown sources need telemetry, not a zero assumption.")
	}
	if *bundle != "" {
		settings := map[string]string{}
		flag.CommandLine.VisitAll(func(fl *flag.Flag) { settings[fl.Name] = fl.Value.String() })
		if err := health.WriteSupport(*bundle, snapshot, settings); err != nil {
			fmt.Fprintln(os.Stderr, "doctor: could not write support archive")
			return 1
		}
	}
	result := 0
	inspect := func(checks []health.Check) {
		for _, c := range checks {
			switch c.State {
			case health.Degraded, health.Unavailable, health.Stale:
				result = 2
			case health.Unknown:
				if result == 0 {
					result = 3
				}
			}
		}
	}
	inspect(snapshot.Checks)
	for _, n := range snapshot.Nodes {
		inspect(n.Checks)
	}
	return result
}
