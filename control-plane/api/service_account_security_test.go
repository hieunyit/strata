package api

import (
	"bytes"
	"context"
	"github.com/strata/strata/control-plane/ingest"
	"github.com/strata/strata/control-plane/localauth/localauthtest"
	"github.com/strata/strata/control-plane/store"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestServiceAccountInputLimits(t *testing.T) {
	s := store.New(localauthtest.Pool(t))
	h := NewServer(ServerConfig{Auth: tokenRoles{}, ServiceAccounts: s}, ingest.NewMockEventStore()).Handler()
	for _, tc := range []struct{ name, path, body string }{
		{"duration overflow", "/v1/service-accounts/example-account/tokens", `{"request_id":"invalid-input","etag":"example-etag","scopes":["events:read"],"ttl_seconds":18446744074}`},
		{"negative duration", "/v1/service-accounts/example-account/tokens", `{"request_id":"invalid-input","etag":"example-etag","scopes":["events:read"],"ttl_seconds":-1}`},
		{"trailing JSON", "/v1/service-accounts/example-account/tokens", `{"request_id":"invalid-input","etag":"example-etag","scopes":["events:read"]}{"scopes":["*"]}`},
		{"oversized body", "/v1/service-accounts", `{"name":"` + strings.Repeat("a", 65536) + `"}`},
		{"unknown role", "/v1/service-accounts", `{"id":"example-new","name":"Example","roles":["superuser"]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, tc.path, bytes.NewBufferString(tc.body))
			req.Header.Set("Authorization", "Bearer admin")
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("got %d, want 400", rec.Code)
			}
		})
	}
	tokens, err := s.ListTokens(context.Background(), "example-account")
	if err != nil {
		t.Fatal(err)
	}
	if len(tokens) != 0 {
		t.Fatal("invalid requests issued credentials")
	}
}
