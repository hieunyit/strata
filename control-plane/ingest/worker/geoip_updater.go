package worker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/strata/strata/control-plane/ingest"
	"github.com/strata/strata/control-plane/policy"
)

// GeoIPUpdater periodically checks, validates, and synchronizes GeoIP databases (.mmdb) to MinIO.
type GeoIPUpdater struct {
	mu           sync.Mutex
	sourceURL    string
	objects      policy.Objects
	enricher     *ingest.GeoIPEnricher
	httpClient   *http.Client
	lastSHA256   string
	lastSyncTime time.Time
}

// NewGeoIPUpdater creates a GeoIP database synchronizer.
func NewGeoIPUpdater(sourceURL string, objects policy.Objects, enricher *ingest.GeoIPEnricher) *GeoIPUpdater {
	return &GeoIPUpdater{
		sourceURL:  sourceURL,
		objects:    objects,
		enricher:   enricher,
		httpClient: &http.Client{Timeout: 60 * time.Second},
	}
}

// SetHTTPClient allows overriding the default client for testing.
func (u *GeoIPUpdater) SetHTTPClient(client *http.Client) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.httpClient = client
}

// Sync fetches the latest mmdb, verifies integrity, stores version in MinIO, and reloads enricher.
func (u *GeoIPUpdater) Sync(ctx context.Context) (string, error) {
	u.mu.Lock()
	defer u.mu.Unlock()

	if u.sourceURL == "" {
		return "", errors.New("source URL is empty")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.sourceURL, nil)
	if err != nil {
		return "", fmt.Errorf("creating http request: %w", err)
	}

	resp, err := u.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("downloading geoip database: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download failed with status %d", resp.StatusCode)
	}

	const maxGeoIPDownloadSize = 256 * 1024 * 1024 // 256 MB upper limit
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxGeoIPDownloadSize+1))
	if err != nil {
		return "", fmt.Errorf("reading geoip response: %w", err)
	}
	if len(data) > maxGeoIPDownloadSize {
		return "", errors.New("geoip database exceeds maximum allowed size (256 MB)")
	}

	if len(data) < 16 {
		return "", errors.New("geoip database payload too small")
	}

	hash := sha256.Sum256(data)
	shaHex := hex.EncodeToString(hash[:])

	// If identical to last hash, skip re-uploading
	if shaHex == u.lastSHA256 && u.lastSHA256 != "" {
		return shaHex, nil
	}

	now := time.Now().UTC()
	key := fmt.Sprintf("geoip/geoip-%s-%s.mmdb", now.Format("20060102"), shaHex[:8])

	if u.objects != nil {
		if err := u.objects.Put(ctx, key, data, shaHex); err != nil {
			return "", fmt.Errorf("storing geoip in object storage: %w", err)
		}
	}

	if u.enricher != nil {
		u.enricher.ResetCache()
	}

	u.lastSHA256 = shaHex
	u.lastSyncTime = now

	return shaHex, nil
}

// LastSync returns the last synchronization timestamp and SHA-256.
func (u *GeoIPUpdater) LastSync() (time.Time, string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.lastSyncTime, u.lastSHA256
}
