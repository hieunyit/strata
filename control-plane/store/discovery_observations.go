package store

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/strata/strata/control-plane/apidiscovery"
	"strings"
	"time"
)

func (s *Store) SaveDiscoveryBatch(ctx context.Context, app, env, scope, batch, collector string, samples []apidiscovery.Sample) error {
	if !appID.MatchString(app) || !appID.MatchString(env) || batch == "" || len(batch) > 128 || !strings.HasPrefix(collector, "sa:") || len(collector) > 128 || len(samples) == 0 || len(samples) > 100 {
		return fmt.Errorf("discovery: invalid batch")
	}
	raw, err := json.Marshal(struct {
		App, Env, Scope string
		Samples         []apidiscovery.Sample
	}{app, env, scope, samples})
	if err != nil {
		return err
	}
	sum := sha256.Sum256(raw)
	return s.inTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(744001)`); err != nil {
			return err
		}
		var old []byte
		err := tx.QueryRow(ctx, `SELECT fingerprint FROM discovery_batches WHERE collector_subject=$1 AND batch_id=$2`, collector, batch).Scan(&old)
		if err == nil {
			if string(old) != string(sum[:]) {
				return ErrRequestReused
			}
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		var current bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM applications a JOIN application_environments e ON e.application_id=a.id WHERE a.id=$1 AND e.id=$2 AND a.etag=$3)`, app, env, scope).Scan(&current); err != nil {
			return err
		}
		if !current {
			return ErrEtagMismatch
		}
		var total, own, batches int
		if err = tx.QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE application_id=$1 AND environment_id=$2) FROM discovery_observations`, app, env).Scan(&total, &own); err != nil {
			return err
		}
		if err = tx.QueryRow(ctx, `SELECT count(*) FROM discovery_batches`).Scan(&batches); err != nil {
			return err
		}
		if total+len(samples) > 100000 || own+len(samples) > 10000 || batches >= 10000 {
			return fmt.Errorf("discovery: observation quota")
		}
		endpoints := map[string]bool{}
		rows, err := tx.Query(ctx, `SELECT DISTINCT route_id,method,path FROM discovery_observations WHERE application_id=$1 AND environment_id=$2 AND scope_etag=$3`, app, env, scope)
		if err != nil {
			return err
		}
		for rows.Next() {
			var route, method, path string
			if err = rows.Scan(&route, &method, &path); err != nil {
				rows.Close()
				return err
			}
			endpoints[route+"/"+method+"/"+path] = true
		}
		rows.Close()
		if err = rows.Err(); err != nil {
			return err
		}
		for _, v := range samples {
			if !appID.MatchString(v.RouteID) || len(v.Path) > 512 || len(v.Source) != 64 || len(v.Key) != 64 {
				return fmt.Errorf("discovery: invalid normalized sample")
			}
			endpoints[v.RouteID+"/"+v.Method+"/"+v.Path] = true
			if len(endpoints) > 1000 {
				return fmt.Errorf("discovery: endpoint quota")
			}
			if _, err = tx.Exec(ctx, `INSERT INTO discovery_observations(application_id,environment_id,scope_etag,route_id,method,path,content_type,body_bytes,source_hash,at,observation_key) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT(observation_key) DO NOTHING`, app, env, scope, v.RouteID, v.Method, v.Path, v.ContentType, v.BodyBytes, v.Source, v.At, v.Key); err != nil {
				return err
			}
		}
		if _, err = tx.Exec(ctx, `INSERT INTO discovery_batches(collector_subject,batch_id,fingerprint) VALUES($1,$2,$3)`, collector, batch, sum[:]); err != nil {
			return err
		}
		return writeAudit(ctx, tx, Audit{Actor: "collector", Subject: collector, Channel: "system", Action: "discovery.observed", Resource: "applications/" + app, After: map[string]any{"count": len(samples)}})
	})
}

type DiscoveredEndpoint struct {
	Key                  string    `json:"key"`
	RouteID              string    `json:"route_id"`
	Method               string    `json:"method"`
	Path                 string    `json:"path"`
	ContentTypes         []string  `json:"content_types"`
	Samples              int64     `json:"samples"`
	IndependentSources   int       `json:"independent_sources"`
	FirstSeen            time.Time `json:"first_seen"`
	LastSeen             time.Time `json:"last_seen"`
	ObservedMaxBodyBytes int64     `json:"observed_max_body_bytes"`
	Eligible             bool      `json:"eligible"`
}
type discoveryQuery interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

func (s *Store) DiscoveredEndpoints(ctx context.Context, app, env, scope string, now time.Time) ([]DiscoveredEndpoint, error) {
	return discoveredEndpoints(ctx, s.pool, app, env, scope, now)
}
func discoveredEndpoints(ctx context.Context, q discoveryQuery, app, env, scope string, now time.Time) ([]DiscoveredEndpoint, error) {
	rows, err := q.Query(ctx, `WITH eligible AS(SELECT * FROM discovery_observations WHERE application_id=$1 AND environment_id=$2 AND scope_etag=$3 AND expires_at>$4), daily AS(SELECT route_id,method,path,date_trunc('day',at AT TIME ZONE 'UTC'),count(DISTINCT source_hash) sources FROM eligible GROUP BY 1,2,3,4), sources AS(SELECT route_id,method,path,max(sources) sources FROM daily GROUP BY 1,2,3)
 SELECT e.route_id,e.method,e.path,array_agg(DISTINCT e.content_type ORDER BY e.content_type),count(*),s.sources,min(e.at),max(e.at),max(e.body_bytes) FROM eligible e JOIN sources s USING(route_id,method,path) GROUP BY e.route_id,e.method,e.path,s.sources ORDER BY e.route_id,e.path,e.method LIMIT 1001`, app, env, scope, now)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (DiscoveredEndpoint, error) {
		var v DiscoveredEndpoint
		err := r.Scan(&v.RouteID, &v.Method, &v.Path, &v.ContentTypes, &v.Samples, &v.IndependentSources, &v.FirstSeen, &v.LastSeen, &v.ObservedMaxBodyBytes)
		v.Key = apidiscovery.Digest([]apidiscovery.Operation{{Path: v.RouteID + v.Path, Method: v.Method}})
		v.Eligible = v.Samples >= 20 && v.IndependentSources >= 3 && v.LastSeen.Sub(v.FirstSeen) >= 10*time.Minute
		return v, err
	})
}
func (s *Store) RetainDiscovery(ctx context.Context, now time.Time) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		for _, query := range []string{`DELETE FROM discovery_observations WHERE expires_at<=$1`, `DELETE FROM discovery_proposals WHERE expires_at<=$1`, `DELETE FROM discovery_batches WHERE created_at<=$1::timestamptz-interval '7 days'`} {
			if _, err := tx.Exec(ctx, query, now); err != nil {
				return err
			}
		}
		return nil
	})
}
