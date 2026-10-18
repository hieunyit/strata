package schema

import (
	"testing"
)

const samplePetstoreYAML = `
openapi: 3.0.0
info:
  title: Swagger Petstore
  version: 1.0.0
  description: Sample petstore API for Strata testing
paths:
  /pets:
    get:
      summary: List all pets
      parameters:
        - name: limit
          in: query
          required: false
          schema:
            type: integer
        - name: status
          in: query
          required: false
          schema:
            type: string
    post:
      summary: Create a pet
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required:
                - name
                - category
              properties:
                name:
                  type: string
                category:
                  type: string
                tag:
                  type: string
  /pets/{id}:
    get:
      summary: Info for a specific pet
    delete:
      summary: Delete a pet
`

const sampleUsersJSON = `{
  "openapi": "3.1.0",
  "info": {
    "title": "User Service",
    "version": "2.0.0"
  },
  "paths": {
    "/api/v1/users": {
      "get": {
        "parameters": [
          {
            "name": "role",
            "in": "query"
          }
        ]
      },
      "post": {
        "requestBody": {
          "content": {
            "application/json": {
              "schema": {
                "required": ["email", "password"],
                "properties": {
                  "email": {"type": "string"},
                  "password": {"type": "string"},
                  "age": {"type": "integer"}
                }
              }
            }
          }
        }
      }
    }
  }
}`

func TestParseOpenAPI_YAML(t *testing.T) {
	s, err := ParseOpenAPI("petstore", []byte(samplePetstoreYAML))
	if err != nil {
		t.Fatalf("unexpected error parsing YAML: %v", err)
	}

	if s.ID != "petstore" {
		t.Errorf("expected ID 'petstore', got %q", s.ID)
	}
	if s.Name != "Swagger Petstore" {
		t.Errorf("expected Name 'Swagger Petstore', got %q", s.Name)
	}
	if s.Version != "1.0.0" {
		t.Errorf("expected Version '1.0.0', got %q", s.Version)
	}
	if s.Format != FormatOpenAPI3YAML {
		t.Errorf("expected format YAML, got %v", s.Format)
	}
	if len(s.Endpoints) != 2 {
		t.Fatalf("expected 2 endpoints, got %d", len(s.Endpoints))
	}

	// /pets endpoint check
	petsEp := s.Endpoints[0]
	if petsEp.PathPattern != "/pets" {
		t.Errorf("expected path '/pets', got %q", petsEp.PathPattern)
	}
	if len(petsEp.Methods) != 2 || petsEp.Methods[0] != "GET" || petsEp.Methods[1] != "POST" {
		t.Errorf("expected methods [GET, POST], got %v", petsEp.Methods)
	}
	if len(petsEp.AllowedQueryParams) != 2 {
		t.Errorf("expected 2 query params (limit, status), got %v", petsEp.AllowedQueryParams)
	}
	if len(petsEp.RequiredFields) != 2 {
		t.Errorf("expected 2 required fields (category, name), got %v", petsEp.RequiredFields)
	}
	if len(petsEp.AllowedFields) != 3 {
		t.Errorf("expected 3 allowed fields, got %v", petsEp.AllowedFields)
	}
}

func TestParseOpenAPI_JSON(t *testing.T) {
	s, err := ParseOpenAPI("users-api", []byte(sampleUsersJSON))
	if err != nil {
		t.Fatalf("unexpected error parsing JSON: %v", err)
	}

	if s.ID != "users-api" {
		t.Errorf("expected ID 'users-api', got %q", s.ID)
	}
	if s.Name != "User Service" {
		t.Errorf("expected Name 'User Service', got %q", s.Name)
	}
	if s.Format != FormatOpenAPI3JSON {
		t.Errorf("expected format JSON, got %v", s.Format)
	}
	if len(s.Endpoints) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(s.Endpoints))
	}

	ep := s.Endpoints[0]
	if ep.PathPattern != "/api/v1/users" {
		t.Errorf("expected '/api/v1/users', got %q", ep.PathPattern)
	}
	if len(ep.AllowedQueryParams) != 1 || ep.AllowedQueryParams[0] != "role" {
		t.Errorf("expected query param 'role', got %v", ep.AllowedQueryParams)
	}
	if len(ep.RequiredFields) != 2 {
		t.Errorf("expected 2 required fields (email, password), got %v", ep.RequiredFields)
	}
	if len(ep.AllowedFields) != 3 {
		t.Errorf("expected 3 allowed fields (age, email, password), got %v", ep.AllowedFields)
	}
}

func TestParseOpenAPI_ValidationErrors(t *testing.T) {
	// 1. Invalid ID
	if _, err := ParseOpenAPI("INVALID_ID!", []byte(sampleUsersJSON)); err == nil {
		t.Error("expected error for invalid ID")
	}

	// 2. Empty data
	if _, err := ParseOpenAPI("test", []byte("")); err == nil {
		t.Error("expected error for empty data")
	}

	// 3. Swagger 2.0 (unsupported)
	swagger2 := `
swagger: "2.0"
info:
  title: Old API
  version: 1.0
paths:
  /test:
    get:
      summary: test
`
	if _, err := ParseOpenAPI("old", []byte(swagger2)); err == nil {
		t.Error("expected error for Swagger 2.0")
	}

	// 4. Missing paths
	noPaths := `
openapi: 3.0.0
info:
  title: No paths
  version: 1.0
`
	if _, err := ParseOpenAPI("nopaths", []byte(noPaths)); err == nil {
		t.Error("expected error for missing paths")
	}
}

func TestMemoryStore_CRUD(t *testing.T) {
	store := NewMemoryStore()

	s, _ := ParseOpenAPI("petstore", []byte(samplePetstoreYAML))
	if err := store.Save(s); err != nil {
		t.Fatalf("failed to save schema: %v", err)
	}

	// Get
	retrieved, err := store.Get("petstore")
	if err != nil {
		t.Fatalf("failed to get schema: %v", err)
	}
	if retrieved.Name != "Swagger Petstore" {
		t.Errorf("expected 'Swagger Petstore', got %q", retrieved.Name)
	}

	// List
	list, err := store.List()
	if err != nil || len(list) != 1 {
		t.Fatalf("expected 1 item in list, got %d (err: %v)", len(list), err)
	}

	// Delete
	if err := store.Delete("petstore"); err != nil {
		t.Fatalf("failed to delete: %v", err)
	}

	if _, err := store.Get("petstore"); err != ErrNotFound {
		t.Errorf("expected ErrNotFound after deletion, got %v", err)
	}
}
