package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/strata/strata/control-plane/schema"
)

func TestSchemaHandler_Lifecycle(t *testing.T) {
	store := schema.NewMemoryStore()
	handler := NewSchemaHandler(store)

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	// 1. Initial list should be empty
	req := httptest.NewRequest(http.MethodGet, "/v1/schemas", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var list []schema.SchemaSummary
	if err := json.NewDecoder(rec.Body).Decode(&list); err != nil {
		t.Fatalf("failed to decode list: %v", err)
	}
	if len(list) != 0 {
		t.Errorf("expected 0 schemas, got %d", len(list))
	}

	// 2. Upload valid schema
	sampleSpec := `{
		"openapi": "3.0.0",
		"info": {"title": "Users Service", "version": "1.0"},
		"paths": {
			"/users": {
				"get": {"summary": "List users"}
			}
		}
	}`
	uploadPayload := UploadSchemaRequest{
		ID:   "users-service",
		Spec: sampleSpec,
	}
	body, _ := json.Marshal(uploadPayload)

	req = httptest.NewRequest(http.MethodPost, "/v1/schemas", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d: %s", rec.Code, rec.Body.String())
	}

	var created schema.ApiSchema
	if err := json.NewDecoder(rec.Body).Decode(&created); err != nil {
		t.Fatalf("failed to decode created schema: %v", err)
	}
	if created.ID != "users-service" || len(created.Endpoints) != 1 {
		t.Errorf("unexpected created schema: %+v", created)
	}

	// 3. Get schema detail
	req = httptest.NewRequest(http.MethodGet, "/v1/schemas/users-service", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}

	// 4. Delete schema
	req = httptest.NewRequest(http.MethodDelete, "/v1/schemas/users-service", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204 No Content, got %d", rec.Code)
	}

	// 5. Verify deleted returns 404
	req = httptest.NewRequest(http.MethodGet, "/v1/schemas/users-service", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 Not Found, got %d", rec.Code)
	}
}

func TestSchemaHandler_InvalidSpec(t *testing.T) {
	store := schema.NewMemoryStore()
	handler := NewSchemaHandler(store)
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	// Upload invalid spec (missing openapi version)
	uploadPayload := UploadSchemaRequest{
		ID:   "invalid-api",
		Spec: `{"paths": {}}`,
	}
	body, _ := json.Marshal(uploadPayload)

	req := httptest.NewRequest(http.MethodPost, "/v1/schemas", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request, got %d", rec.Code)
	}
}
