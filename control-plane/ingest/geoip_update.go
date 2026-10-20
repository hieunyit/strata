package ingest

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// GeoIP database updates (W17-G2-01, nginx-module.md › Bản đồ GeoIP): the
// control plane downloads the City and ASN databases on a schedule (weekly
// by default), checks them like the files given at start (type, structure,
// size), keeps each version in object storage and switches the enricher to
// it. Every replica runs it; versions are content-addressed, so concurrent
// runs store the same objects.
//
// Objects: geoip/<version>/{city,asn}.mmdb, geoip/<version>/manifest.json
// and geoip/latest.json (a copy of the latest manifest). <version> is the
// fingerprint events carry (MMDBReader.Version).

// MaxGeoIPDownloadBytes bounds one download (a .tar.gz of MaxMind or a
// plain .mmdb).
const MaxGeoIPDownloadBytes = 256 << 20

// geoIPUnzipLimit bounds a decompressed download: one database plus the
// headers and license texts of its archive (a variable for tests).
var geoIPUnzipLimit = MaxGeoIPDatabaseBytes + 1<<20

// GeoIPObjects is the object store (policy.S3 in the server).
type GeoIPObjects interface {
	Put(ctx context.Context, key string, data []byte, sha256hex string) error
	Get(ctx context.Context, key string) ([]byte, error)
}

// GeoIPManifest describes a stored version.
type GeoIPManifest struct {
	Version     string    `json:"version"`
	FetchedAt   time.Time `json:"fetched_at"`
	CitySHA256  string    `json:"city_sha256,omitempty"`
	ASNSHA256   string    `json:"asn_sha256,omitempty"`
	CitySource  string    `json:"city_source,omitempty"`
	ASNSource   string    `json:"asn_source,omitempty"`
	CityBuiltAt time.Time `json:"city_built_at,omitzero"`
	ASNBuiltAt  time.Time `json:"asn_built_at,omitzero"`
}

// GeoIPUpdater downloads, checks, stores and activates GeoIP databases.
type GeoIPUpdater struct {
	// CityURL, ASNURL: http(s) URLs of a .mmdb or of a .tar.gz holding one
	// (MaxMind's download URLs carry the license key in the query: they
	// are never logged or stored with it). At least one.
	CityURL, ASNURL string
	Objects         GeoIPObjects
	Enricher        *GeoIPEnricher
	Client          *http.Client // default: 10 minute timeout
	Now             func() time.Time
	// PruneOld, when set, is called after a new version is stored and
	// active, with it and the version it replaced: it removes the other
	// stored versions (CP-A07, policy.PruneGeoIP). An object store with a
	// lifecycle rule leaves it nil.
	PruneOld func(ctx context.Context, keep []string) error

	mu          sync.Mutex // one update at a time
	lastSuccess atomic.Int64
	failures    atomic.Uint64
}

// LastSuccess is the time of the last update that ended well (unchanged
// included); zero before one.
func (u *GeoIPUpdater) LastSuccess() time.Time {
	if ns := u.lastSuccess.Load(); ns != 0 {
		return time.Unix(0, ns).UTC()
	}
	return time.Time{}
}

// Failures counts the updates and loads that failed.
func (u *GeoIPUpdater) Failures() uint64 { return u.failures.Load() }

func (u *GeoIPUpdater) now() time.Time {
	if u.Now != nil {
		return u.Now().UTC()
	}
	return time.Now().UTC()
}

const geoIPLatestKey = "geoip/latest.json"

// LoadLatest activates the version in geoip/latest.json, as stored by any
// replica. It returns the manifest, or nil when there is none yet.
func (u *GeoIPUpdater) LoadLatest(ctx context.Context) (*GeoIPManifest, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	raw, err := u.Objects.Get(ctx, geoIPLatestKey)
	if err != nil || len(raw) == 0 {
		return nil, nil // nothing stored yet (or not readable): download
	}
	var m GeoIPManifest
	if err := json.Unmarshal(raw, &m); err != nil || !validHex(m.Version) {
		u.failures.Add(1)
		return nil, fmt.Errorf("GeoIP %s: invalid manifest", geoIPLatestKey)
	}
	if m.Version == u.Enricher.Version() {
		return &m, nil
	}
	var data [2][]byte
	for i, f := range []struct{ name, sum string }{{"city", m.CitySHA256}, {"asn", m.ASNSHA256}} {
		if f.sum == "" {
			continue
		}
		b, err := u.Objects.Get(ctx, fmt.Sprintf("geoip/%s/%s.mmdb", m.Version, f.name))
		if err != nil {
			u.failures.Add(1)
			return nil, fmt.Errorf("GeoIP %s database of version %s: %w", f.name, m.Version, err)
		}
		if sum := sha256.Sum256(b); hex.EncodeToString(sum[:]) != f.sum {
			u.failures.Add(1)
			return nil, fmt.Errorf("GeoIP %s database of version %s: SHA-256 differs from its manifest", f.name, m.Version)
		}
		data[i] = b
	}
	reader, err := NewMMDBReaderBytes(ctx, data[0], data[1])
	if err != nil {
		u.failures.Add(1)
		return nil, err
	}
	if reader.Version() != m.Version {
		u.failures.Add(1)
		return nil, fmt.Errorf("GeoIP version %s: stored databases give %s", m.Version, reader.Version())
	}
	u.Enricher.SetReader(reader)
	return &m, nil
}

// Update downloads the databases and, when they differ from the active
// version, checks, stores and activates them. A failure at any step leaves
// the active version as it is. Returns the version now active and whether
// it changed.
func (u *GeoIPUpdater) Update(ctx context.Context) (string, bool, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	prev := u.Enricher.Version()
	version, changed, err := u.update(ctx)
	if err != nil {
		u.failures.Add(1)
		return u.Enricher.Version(), false, err
	}
	if changed && u.PruneOld != nil {
		if err := u.PruneOld(ctx, []string{version, prev}); err != nil {
			log.Printf("[WARN] GeoIP: removing old versions: %v", err)
		}
	}
	u.lastSuccess.Store(u.now().UnixNano())
	return version, changed, nil
}

func (u *GeoIPUpdater) update(ctx context.Context) (string, bool, error) {
	if u.CityURL == "" && u.ASNURL == "" {
		return "", false, errors.New("GeoIP update: no source URL")
	}
	m := GeoIPManifest{FetchedAt: u.now()}
	var data [2][]byte
	for i, src := range []string{u.CityURL, u.ASNURL} {
		if src == "" {
			continue
		}
		archive, err := u.download(ctx, src)
		if err != nil {
			return "", false, err
		}
		db, err := ExtractMMDB(archive)
		if err != nil {
			return "", false, fmt.Errorf("GeoIP download %s: %w", RedactURL(src), err)
		}
		data[i] = db
		sum := sha256.Sum256(db)
		if i == 0 {
			m.CitySHA256, m.CitySource = hex.EncodeToString(sum[:]), RedactURL(src)
		} else {
			m.ASNSHA256, m.ASNSource = hex.EncodeToString(sum[:]), RedactURL(src)
		}
	}
	reader, err := NewMMDBReaderBytes(ctx, data[0], data[1])
	if err != nil {
		return "", false, err
	}
	m.Version = reader.Version()
	if m.Version == u.Enricher.Version() {
		return m.Version, false, nil
	}
	if reader.city != nil {
		m.CityBuiltAt = time.Unix(int64(reader.city.Metadata.BuildEpoch), 0).UTC()
	}
	if reader.asn != nil {
		m.ASNBuiltAt = time.Unix(int64(reader.asn.Metadata.BuildEpoch), 0).UTC()
	}
	for i, name := range []string{"city", "asn"} {
		if data[i] == nil {
			continue
		}
		sum := sha256.Sum256(data[i])
		key := fmt.Sprintf("geoip/%s/%s.mmdb", m.Version, name)
		if err := u.Objects.Put(ctx, key, data[i], hex.EncodeToString(sum[:])); err != nil {
			return "", false, fmt.Errorf("GeoIP: storing %s: %w", key, err)
		}
	}
	manifest, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return "", false, err
	}
	sum := sha256.Sum256(manifest)
	for _, key := range []string{fmt.Sprintf("geoip/%s/manifest.json", m.Version), geoIPLatestKey} {
		if err := u.Objects.Put(ctx, key, manifest, hex.EncodeToString(sum[:])); err != nil {
			return "", false, fmt.Errorf("GeoIP: storing %s: %w", key, err)
		}
	}
	// stored first: a replica starting now loads the same version
	u.Enricher.SetReader(reader)
	return m.Version, true, nil
}

func (u *GeoIPUpdater) download(ctx context.Context, src string) ([]byte, error) {
	safe := RedactURL(src)
	p, err := url.Parse(src)
	if err != nil || (p.Scheme != "http" && p.Scheme != "https") || p.Host == "" {
		return nil, fmt.Errorf("GeoIP download %s: only http(s) URLs", safe)
	}
	client := u.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Minute}
	}
	c := *client
	c.CheckRedirect = func(r *http.Request, via []*http.Request) error {
		if len(via) >= 5 || (r.URL.Scheme != "http" && r.URL.Scheme != "https") {
			return errors.New("redirect refused")
		}
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src, nil)
	if err != nil {
		return nil, fmt.Errorf("GeoIP download %s: bad request", safe)
	}
	resp, err := c.Do(req)
	if err != nil {
		// *url.Error prints the URL, license key included
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return nil, fmt.Errorf("GeoIP download %s: %w", safe, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GeoIP download %s: HTTP %d", safe, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, MaxGeoIPDownloadBytes+1))
	if err != nil {
		return nil, fmt.Errorf("GeoIP download %s: %w", safe, err)
	}
	if len(b) > MaxGeoIPDownloadBytes {
		return nil, fmt.Errorf("GeoIP download %s: larger than 256 MiB", safe)
	}
	return b, nil
}

// ExtractMMDB returns the database in a download: the bytes themselves, or
// the one .mmdb file of a (gzip-compressed) tar archive, as MaxMind ships
// them. Sizes are bounded (MaxGeoIPDatabaseBytes).
func ExtractMMDB(b []byte) ([]byte, error) {
	if len(b) >= 2 && b[0] == 0x1f && b[1] == 0x8b {
		zr, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			return nil, fmt.Errorf("gzip: %w", err)
		}
		d, err := io.ReadAll(io.LimitReader(zr, int64(geoIPUnzipLimit)+1))
		if err != nil {
			return nil, fmt.Errorf("gzip: %w", err)
		}
		if len(d) > geoIPUnzipLimit {
			return nil, errors.New("decompressed size above the limit")
		}
		b = d
	}
	if len(b) > 262 && string(b[257:262]) == "ustar" {
		var found []byte
		tr := tar.NewReader(bytes.NewReader(b))
		for {
			h, err := tr.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return nil, fmt.Errorf("tar: %w", err)
			}
			if h.Typeflag != tar.TypeReg || !strings.HasSuffix(h.Name, ".mmdb") {
				continue
			}
			if found != nil {
				return nil, errors.New("tar holds more than one .mmdb")
			}
			if h.Size > MaxGeoIPDatabaseBytes {
				return nil, errors.New("database above 128 MiB")
			}
			if found, err = io.ReadAll(io.LimitReader(tr, h.Size)); err != nil {
				return nil, fmt.Errorf("tar: %w", err)
			}
		}
		if found == nil {
			return nil, errors.New("tar holds no .mmdb")
		}
		return found, nil
	}
	if len(b) > MaxGeoIPDatabaseBytes {
		return nil, errors.New("database above 128 MiB")
	}
	return b, nil
}

// RedactURL drops the query, fragment and user info of a URL (MaxMind's
// license key is a query parameter).
func RedactURL(s string) string {
	p, err := url.Parse(s)
	if err != nil {
		return "(invalid URL)"
	}
	p.User, p.RawQuery, p.Fragment = nil, "", ""
	return p.String()
}

func validHex(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// Run loads the stored version, then updates now if it is older than
// every, and then every every; a failed update is retried after an hour
// (or every, if shorter). Logs only: GeoIP never stops event ingest.
func (u *GeoIPUpdater) Run(ctx context.Context, every time.Duration) {
	next := time.Duration(0)
	m, err := u.LoadLatest(ctx)
	switch {
	case err != nil:
		log.Printf("[WARN] GeoIP: loading the stored version: %v", err)
	case m != nil:
		log.Printf("[INFO] GeoIP: version %s from %s (fetched %s)", m.Version[:12], geoIPLatestKey, m.FetchedAt.Format(time.RFC3339))
		if age := u.now().Sub(m.FetchedAt); age < every {
			next = every - age
			u.lastSuccess.Store(m.FetchedAt.UnixNano())
		}
	}
	retry := min(time.Hour, every)
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(next):
		}
		v, changed, err := u.Update(ctx)
		switch {
		case err != nil:
			log.Printf("[WARN] GeoIP update: %v (retry in %s)", err, retry)
			next = retry
			continue
		case changed:
			log.Printf("[INFO] GeoIP update: version %s active and stored", v[:12])
		default:
			log.Printf("[INFO] GeoIP update: version %s unchanged", v[:min(12, len(v))])
		}
		next = every
	}
}
