package schema

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// ParseOpenAPI parses and validates an OpenAPI 3.x specification from bytes (JSON or YAML).
func ParseOpenAPI(id string, data []byte) (*ApiSchema, error) {
	if !SchemaIDPattern.MatchString(id) {
		return nil, fmt.Errorf("%w: invalid schema id %q (must be 1-63 chars alphanumeric)", ErrInvalidSchema, id)
	}

	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("%w: empty specification", ErrInvalidSchema)
	}

	var format Format
	if trimmed[0] == '{' {
		format = FormatOpenAPI3JSON
	} else {
		format = FormatOpenAPI3YAML
	}

	var root map[string]interface{}
	if err := yaml.Unmarshal(trimmed, &root); err != nil {
		return nil, fmt.Errorf("%w: failed to parse format: %v", ErrInvalidSchema, err)
	}

	// Validate openapi version
	rawVersion, ok := root["openapi"]
	if !ok {
		return nil, fmt.Errorf("%w: missing 'openapi' version attribute (must be OpenAPI 3.x)", ErrInvalidSchema)
	}
	versionStr, _ := rawVersion.(string)
	if !strings.HasPrefix(versionStr, "3.") {
		return nil, fmt.Errorf("%w: unsupported OpenAPI version %q (must be 3.x)", ErrInvalidSchema, versionStr)
	}

	// Extract info metadata
	name := id
	version := "1.0.0"
	description := ""

	if info, ok := root["info"].(map[string]interface{}); ok {
		if t, ok := info["title"].(string); ok && t != "" {
			name = t
		}
		if v, ok := info["version"].(string); ok && v != "" {
			version = v
		}
		if d, ok := info["description"].(string); ok {
			description = d
		}
	}

	// Extract paths and operations
	rawPaths, ok := root["paths"].(map[string]interface{})
	if !ok || len(rawPaths) == 0 {
		return nil, fmt.Errorf("%w: specification must contain at least one valid path in 'paths'", ErrInvalidSchema)
	}

	// Sort path keys for determinism
	pathKeys := make([]string, 0, len(rawPaths))
	for p := range rawPaths {
		pathKeys = append(pathKeys, p)
	}
	sort.Strings(pathKeys)

	endpoints := make([]ApiEndpoint, 0, len(pathKeys))

	for _, pathPattern := range pathKeys {
		pathObj, ok := rawPaths[pathPattern].(map[string]interface{})
		if !ok {
			continue
		}

		methods := make([]string, 0)
		queryParams := make(map[string]struct{})
		requiredBodyFields := make(map[string]struct{})
		allowedBodyFields := make(map[string]struct{})
		summary := ""

		validHttpMethods := []string{"get", "post", "put", "delete", "patch", "head", "options"}

		for _, m := range validHttpMethods {
			opRaw, ok := pathObj[m]
			if !ok {
				continue
			}
			methods = append(methods, strings.ToUpper(m))

			opObj, ok := opRaw.(map[string]interface{})
			if !ok {
				continue
			}

			if summary == "" {
				if s, ok := opObj["summary"].(string); ok {
					summary = s
				}
			}

			// Extract query parameters
			if paramsRaw, ok := opObj["parameters"].([]interface{}); ok {
				for _, pRaw := range paramsRaw {
					if pMap, ok := pRaw.(map[string]interface{}); ok {
						if in, ok := pMap["in"].(string); ok && strings.EqualFold(in, "query") {
							if pName, ok := pMap["name"].(string); ok && pName != "" {
								queryParams[pName] = struct{}{}
							}
						}
					}
				}
			}

			// Extract requestBody JSON properties
			if reqBody, ok := opObj["requestBody"].(map[string]interface{}); ok {
				if content, ok := reqBody["content"].(map[string]interface{}); ok {
					// Check application/json or */*+json
					for contentType, mediaObjRaw := range content {
						if strings.Contains(strings.ToLower(contentType), "json") {
							if mediaObj, ok := mediaObjRaw.(map[string]interface{}); ok {
								if schemaObj, ok := mediaObj["schema"].(map[string]interface{}); ok {
									extractSchemaFields(schemaObj, requiredBodyFields, allowedBodyFields)
								}
							}
						}
					}
				}
			}
		}

		if len(methods) == 0 {
			continue
		}

		sortedQueryParams := make([]string, 0, len(queryParams))
		for p := range queryParams {
			sortedQueryParams = append(sortedQueryParams, p)
		}
		sort.Strings(sortedQueryParams)

		sortedRequiredFields := make([]string, 0, len(requiredBodyFields))
		for f := range requiredBodyFields {
			sortedRequiredFields = append(sortedRequiredFields, f)
		}
		sort.Strings(sortedRequiredFields)

		sortedAllowedFields := make([]string, 0, len(allowedBodyFields))
		for f := range allowedBodyFields {
			sortedAllowedFields = append(sortedAllowedFields, f)
		}
		sort.Strings(sortedAllowedFields)

		endpoints = append(endpoints, ApiEndpoint{
			PathPattern:        pathPattern,
			Methods:            methods,
			AllowedQueryParams: sortedQueryParams,
			AllowExtraParams:   false,
			RequiredFields:     sortedRequiredFields,
			AllowedFields:      sortedAllowedFields,
			AllowExtraFields:   false,
			Summary:            summary,
		})
	}

	if len(endpoints) == 0 {
		return nil, fmt.Errorf("%w: no valid HTTP operations found in 'paths'", ErrInvalidSchema)
	}

	now := time.Now().UTC()
	return &ApiSchema{
		ID:          id,
		Name:        name,
		Version:     version,
		Description: description,
		Format:      format,
		RawSpec:     string(trimmed),
		Endpoints:   endpoints,
		CreatedAt:   now,
		UpdatedAt:   now,
	}, nil
}

// Helper to extract required and allowed fields from JSON schema properties
func extractSchemaFields(schemaObj map[string]interface{}, requiredFields, allowedFields map[string]struct{}) {
	if reqList, ok := schemaObj["required"].([]interface{}); ok {
		for _, r := range reqList {
			if rStr, ok := r.(string); ok && rStr != "" {
				requiredFields[rStr] = struct{}{}
				allowedFields[rStr] = struct{}{}
			}
		}
	}

	if props, ok := schemaObj["properties"].(map[string]interface{}); ok {
		for propName := range props {
			allowedFields[propName] = struct{}{}
		}
	}
}

// ToJSON exports the schema to JSON string.
func (s *ApiSchema) ToJSON() ([]byte, error) {
	return json.MarshalIndent(s, "", "  ")
}
