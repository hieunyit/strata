package api

import (
	"github.com/strata/strata/control-plane/health"
	"github.com/strata/strata/control-plane/ingest"
	"testing"
)

func TestSystemHealthRequiresAuthorization(t *testing.T) {
	server := NewServer(ServerConfig{Auth: tokenRoles{}, SystemHealth: &health.Service{}}, ingest.NewMockEventStore())
	code, _ := machineRequest(server.Handler(), "GET", "/v1/health", nil, map[string]string{"Authorization": ""})
	if code != 401 {
		t.Fatalf("anonymous health access: %d", code)
	}
	code, body := machineRequest(server.Handler(), "GET", "/v1/health", nil, map[string]string{"Authorization": "Bearer viewer"})
	if code != 200 {
		t.Fatalf("viewer health: %d %s", code, body)
	}
	code, _ = machineRequest(server.Handler(), "POST", "/v1/health", nil, nil)
	if code != 405 {
		t.Fatal("health accepts mutations")
	}
}
