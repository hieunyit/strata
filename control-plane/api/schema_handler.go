package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/strata/strata/control-plane/schema"
)

// SchemaHandler provides REST endpoints for managing OpenAPI positive security model schemas (W21-G2-01).
type SchemaHandler struct {
	store schema.Store
}

// NewSchemaHandler creates a new SchemaHandler.
func NewSchemaHandler(store schema.Store) *SchemaHandler {
	return &SchemaHandler{store: store}
}

// UploadSchemaRequest is the payload for registering a new OpenAPI spec.
type UploadSchemaRequest struct {
	ID   string `json:"id"`
	Spec string `json:"spec"`
}

// RegisterRoutes registers schema routes with an http.ServeMux.
func (h *SchemaHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/v1/schemas", h.HandleSchemas)
	mux.HandleFunc("/v1/schemas/", h.HandleSchemaDetail)
}

// HandleSchemas handles collection operations: GET /v1/schemas and POST /v1/schemas.
func (h *SchemaHandler) HandleSchemas(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.listSchemas(w, r)
	case http.MethodPost:
		h.uploadSchema(w, r)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed", "")
	}
}

// HandleSchemaDetail handles item operations: GET /v1/schemas/{id} and DELETE /v1/schemas/{id}.
func (h *SchemaHandler) HandleSchemaDetail(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/v1/schemas/")
	if id == "" || strings.Contains(id, "/") {
		writeError(w, http.StatusBadRequest, "invalid schema id", "")
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.getSchema(w, r, id)
	case http.MethodDelete:
		h.deleteSchema(w, r, id)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed", "")
	}
}

func (h *SchemaHandler) listSchemas(w http.ResponseWriter, r *http.Request) {
	schemas, err := h.store.List()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list schemas", err.Error())
		return
	}

	summaries := make([]schema.SchemaSummary, 0, len(schemas))
	for _, s := range schemas {
		summaries = append(summaries, s.Summary())
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(summaries)
}

func (h *SchemaHandler) uploadSchema(w http.ResponseWriter, r *http.Request) {
	var rawSpec []byte
	var id string

	contentType := r.Header.Get("Content-Type")
	if strings.HasPrefix(contentType, "multipart/form-data") {
		// Support file upload via multipart
		if err := r.ParseMultipartForm(10 << 20); err != nil { // 10MB max
			writeError(w, http.StatusBadRequest, "failed to parse multipart form", err.Error())
			return
		}
		id = r.FormValue("id")
		file, _, err := r.FormFile("spec_file")
		if err != nil {
			writeError(w, http.StatusBadRequest, "missing 'spec_file' in form", err.Error())
			return
		}
		defer file.Close()
		rawSpec, err = io.ReadAll(file)
		if err != nil {
			writeError(w, http.StatusBadRequest, "failed to read uploaded file", err.Error())
			return
		}
	} else {
		// Support JSON request payload
		var req UploadSchemaRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid json request body", err.Error())
			return
		}
		id = req.ID
		rawSpec = []byte(req.Spec)
	}

	parsed, err := schema.ParseOpenAPI(id, rawSpec)
	if err != nil {
		writeError(w, http.StatusBadRequest, "schema validation failed", err.Error())
		return
	}

	if err := h.store.Save(parsed); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to store schema", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(parsed)
}

func (h *SchemaHandler) getSchema(w http.ResponseWriter, r *http.Request, id string) {
	s, err := h.store.Get(id)
	if err != nil {
		if errors.Is(err, schema.ErrNotFound) {
			writeError(w, http.StatusNotFound, "schema not found", id)
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to get schema", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(s)
}

func (h *SchemaHandler) deleteSchema(w http.ResponseWriter, r *http.Request, id string) {
	if err := h.store.Delete(id); err != nil {
		if errors.Is(err, schema.ErrNotFound) {
			writeError(w, http.StatusNotFound, "schema not found", id)
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to delete schema", err.Error())
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
