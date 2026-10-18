// Package schema manages OpenAPI schemas for the positive security model (W21-G2-01).
package schema

import (
	"errors"
	"regexp"
	"time"
)

var (
	// SchemaIDPattern validates alphanumeric schema identifiers.
	SchemaIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	// ErrNotFound is returned when an API schema does not exist.
	ErrNotFound = errors.New("schema not found")
	// ErrInvalidSchema is returned when an OpenAPI specification fails validation.
	ErrInvalidSchema = errors.New("invalid openapi schema specification")
)

// Format indicates the format of the uploaded schema definition.
type Format string

const (
	FormatOpenAPI3JSON Format = "openapi3_json"
	FormatOpenAPI3YAML Format = "openapi3_yaml"
)

// ApiSchema represents a parsed and validated OpenAPI positive model schema.
type ApiSchema struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Version     string        `json:"version"`
	Description string        `json:"description,omitempty"`
	Format      Format        `json:"format"`
	RawSpec     string        `json:"raw_spec,omitempty"`
	Endpoints   []ApiEndpoint `json:"endpoints"`
	CreatedAt   time.Time     `json:"created_at"`
	UpdatedAt   time.Time     `json:"updated_at"`
}

// ApiEndpoint describes a protected route and its allowed methods, params, and body fields.
type ApiEndpoint struct {
	PathPattern        string   `json:"path_pattern"`
	Methods            []string `json:"methods"`
	AllowedQueryParams []string `json:"allowed_query_params,omitempty"`
	AllowExtraParams   bool     `json:"allow_extra_params"`
	RequiredFields     []string `json:"required_fields,omitempty"`
	AllowedFields      []string `json:"allowed_fields,omitempty"`
	AllowExtraFields   bool     `json:"allow_extra_fields"`
	Summary            string   `json:"summary,omitempty"`
}

// SchemaSummary provides lightweight metadata for listing registered schemas.
type SchemaSummary struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	Version        string    `json:"version"`
	Description    string    `json:"description,omitempty"`
	Format         Format    `json:"format"`
	EndpointsCount int       `json:"endpoints_count"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// Summary returns a lightweight summary of this ApiSchema.
func (s *ApiSchema) Summary() SchemaSummary {
	return SchemaSummary{
		ID:             s.ID,
		Name:           s.Name,
		Version:        s.Version,
		Description:    s.Description,
		Format:         s.Format,
		EndpointsCount: len(s.Endpoints),
		CreatedAt:      s.CreatedAt,
		UpdatedAt:      s.UpdatedAt,
	}
}
