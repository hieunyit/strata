package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/strata/strata/control-plane/ingest"
)

// A deploy compiles a bundle: with the whole signature package it outlives
// the 10 s read and write timeouts of the REST server. Those timeouts, as
// the server sets them on the connection, must not cancel it; any other
// route still ends at WriteTimeout.
func TestDeployOutlivesServerTimeouts(t *testing.T) {
	const slow = 600 * time.Millisecond
	admin := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(slow):
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{"ok":true}`)
		case <-r.Context().Done():
			// what the compiler sees: killed
			w.WriteHeader(http.StatusGatewayTimeout)
		}
	})
	s := NewServer(ServerConfig{
		Auth:          tokenRoles{},
		Admin:         admin,
		ReadTimeout:   200 * time.Millisecond,
		WriteTimeout:  200 * time.Millisecond,
		DeployTimeout: 5 * time.Second,
	}, ingest.NewMockEventStore())
	ts := httptest.NewUnstartedServer(s.Handler())
	// as cmd/server sets its http.Server, with the short timeouts
	ts.Config.ReadTimeout = 200 * time.Millisecond
	ts.Config.WriteTimeout = 200 * time.Millisecond
	ts.Start()
	defer ts.Close()

	do := func(method, path string) (int, error) {
		req, _ := http.NewRequest(method, ts.URL+path, nil)
		req.Header.Set("Authorization", "Bearer operator")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return 0, err
		}
		defer resp.Body.Close()
		_, _ = io.ReadAll(resp.Body)
		return resp.StatusCode, nil
	}

	if code, err := do(http.MethodPost, "/v1/policies/example-api:deploy"); err != nil || code != http.StatusOK {
		t.Fatalf("deploy longer than the server timeouts: code %d, err %v; want 200", code, err)
	}
	// negative: the same wait on another route is cut at WriteTimeout
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/v1/policies/example-api"},
		{http.MethodPost, "/v1/policies/example-api:validate"},
		{http.MethodGet, "/v1/policies/example-api:deploy"},
	} {
		if code, err := do(c.method, c.path); err == nil && code == http.StatusOK {
			t.Errorf("%s %s: got 200 after %v, want it cut at the 200 ms timeout", c.method, c.path, slow)
		}
	}
}
