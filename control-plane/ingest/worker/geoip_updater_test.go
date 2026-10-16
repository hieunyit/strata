package worker

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

type mockObjects struct {
	mu      sync.Mutex
	stored  map[string][]byte
	hashes  map[string]string
	putCall int
}

func newMockObjects() *mockObjects {
	return &mockObjects{
		stored: make(map[string][]byte),
		hashes: make(map[string]string),
	}
}

func (m *mockObjects) Put(_ context.Context, key string, data []byte, sha256hex string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stored[key] = data
	m.hashes[key] = sha256hex
	m.putCall++
	return nil
}

func (m *mockObjects) Get(_ context.Context, key string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.stored[key]
	if !ok {
		return nil, nil
	}
	return d, nil
}

func TestGeoIPUpdater_Sync(t *testing.T) {
	ctx := context.Background()

	// 1. Mock HTTP server serving dummy .mmdb bytes
	dummyData := []byte("MAXMIND_GEOIP_DUMMY_DATABASE_CONTENT_V1")
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(dummyData)
	}))
	defer ts.Close()

	objects := newMockObjects()
	updater := NewGeoIPUpdater(ts.URL, objects, nil)
	updater.SetHTTPClient(ts.Client())

	// 2. Perform initial sync
	hash1, err := updater.Sync(ctx)
	if err != nil {
		t.Fatalf("first sync failed: %v", err)
	}
	if hash1 == "" {
		t.Errorf("expected non-empty sha256 hash")
	}
	if objects.putCall != 1 {
		t.Errorf("expected 1 upload to object storage, got %d", objects.putCall)
	}

	// 3. Perform second sync with identical data -> should be idempotent, no re-upload
	hash2, err := updater.Sync(ctx)
	if err != nil {
		t.Fatalf("second sync failed: %v", err)
	}
	if hash2 != hash1 {
		t.Errorf("hash mismatch: %s vs %s", hash1, hash2)
	}
	if objects.putCall != 1 {
		t.Errorf("expected objects.putCall to remain 1 on identical data, got %d", objects.putCall)
	}

	lastTime, lastHash := updater.LastSync()
	if lastTime.IsZero() || lastHash != hash1 {
		t.Errorf("unexpected LastSync values: %v, %s", lastTime, lastHash)
	}
}
