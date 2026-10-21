package apidiscovery

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"gopkg.in/yaml.v3"
	"io"
	"mime"
	"regexp"
	"sort"
	"strings"
)

type Operation struct {
	Path         string   `json:"path"`
	Method       string   `json:"method"`
	ContentTypes []string `json:"content_types"`
	MaxBodyBytes int64    `json:"max_body_bytes"`
}

var parameterName = regexp.MustCompile(`^\{[A-Za-z_][A-Za-z0-9_]{0,63}\}$`)
var documentPath = regexp.MustCompile(`^/[A-Za-z0-9_{}./-]*$`)

func ParseDocument(raw []byte) ([]Operation, error) {
	if len(raw) == 0 || len(raw) > 1<<20 {
		return nil, fmt.Errorf("discovery: document size")
	}
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	var root yaml.Node
	if err := decoder.Decode(&root); err != nil {
		return nil, fmt.Errorf("discovery: invalid OpenAPI document")
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("discovery: one document required")
	}
	nodes := 0
	var walk func(*yaml.Node, int) error
	walk = func(n *yaml.Node, depth int) error {
		nodes++
		if nodes > 20000 || depth > 32 || n.Kind == yaml.AliasNode {
			return fmt.Errorf("discovery: document complexity")
		}
		if n.Kind == yaml.MappingNode {
			keys := map[string]bool{}
			for i := 0; i < len(n.Content); i += 2 {
				k := n.Content[i].Value
				if keys[k] {
					return fmt.Errorf("discovery: duplicate key")
				}
				keys[k] = true
				if k == "$ref" && !strings.HasPrefix(n.Content[i+1].Value, "#/") {
					return fmt.Errorf("discovery: external references disabled")
				}
			}
		}
		for _, c := range n.Content {
			if err := walk(c, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(&root, 0); err != nil {
		return nil, err
	}
	var doc struct {
		Info struct {
			Title   string `yaml:"title"`
			Version string `yaml:"version"`
		} `yaml:"info"`
		OpenAPI string                          `yaml:"openapi"`
		Paths   map[string]map[string]yaml.Node `yaml:"paths"`
	}
	if err := root.Decode(&doc); err != nil || (!strings.HasPrefix(doc.OpenAPI, "3.0.") && !strings.HasPrefix(doc.OpenAPI, "3.1.")) || len(doc.Paths) > 1000 || doc.Paths == nil || len(doc.Info.Title) == 0 || len(doc.Info.Title) > 128 || len(doc.Info.Version) == 0 || len(doc.Info.Version) > 64 {
		return nil, fmt.Errorf("discovery: unsupported OpenAPI")
	}
	out := []Operation{}
	for path, items := range doc.Paths {
		if len(path) > 512 || !documentPath.MatchString(path) || strings.Contains(path, "//") {
			return nil, fmt.Errorf("discovery: invalid schema path")
		}
		names := map[string]bool{}
		for _, segment := range strings.Split(path, "/") {
			if segment == "." || segment == ".." {
				return nil, fmt.Errorf("discovery: noncanonical schema path")
			}
			if strings.ContainsAny(segment, "{}") {
				if !parameterName.MatchString(segment) || names[segment] {
					return nil, fmt.Errorf("discovery: unsupported schema parameter")
				}
				names[segment] = true
			}
		}
		for method, node := range items {
			method = strings.ToUpper(method)
			if !methods[method] {
				continue
			}
			var op struct {
				RequestBody struct {
					Content map[string]any `yaml:"content"`
				} `yaml:"requestBody"`
				Max int64 `yaml:"x-strata-observed-max-body-bytes"`
			}
			if err := node.Decode(&op); err != nil {
				return nil, fmt.Errorf("discovery: invalid operation")
			}
			if op.Max < 0 || op.Max > 16<<20 || len(op.RequestBody.Content) > 8 {
				return nil, fmt.Errorf("discovery: invalid schema bounds")
			}
			types := []string{}
			for typ := range op.RequestBody.Content {
				_, _, mediaErr := mime.ParseMediaType(typ)
				if mediaErr != nil || len(typ) > 128 || strings.ContainsAny(typ, "\r\n") {
					return nil, fmt.Errorf("discovery: invalid schema media")
				}
				types = append(types, typ)
			}
			sort.Strings(types)
			out = append(out, Operation{Path: path, Method: method, ContentTypes: types, MaxBodyBytes: op.Max})
		}
	}
	if len(out) > 2000 {
		return nil, fmt.Errorf("discovery: operation limit")
	}
	sortOperations(out)
	return out, nil
}
func sortOperations(out []Operation) {
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].Method < out[j].Method
	})
}
func Digest(ops []Operation) string {
	raw, _ := json.Marshal(ops)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func Matches(template, path string) bool {
	a, b := strings.Split(template, "/"), strings.Split(path, "/")
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if strings.HasPrefix(a[i], "{") && strings.HasSuffix(a[i], "}") {
			continue
		}
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func Document(ops []Operation) (json.RawMessage, error) {
	paths := map[string]map[string]any{}
	for _, op := range ops {
		if paths[op.Path] == nil {
			paths[op.Path] = map[string]any{}
		}
		parameters := []map[string]any{}
		for _, part := range strings.Split(op.Path, "/") {
			if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") {
				parameters = append(parameters, map[string]any{"name": strings.Trim(part, "{}"), "in": "path", "required": true, "schema": map[string]any{"type": "string"}})
			}
		}
		content := map[string]any{}
		for _, typ := range op.ContentTypes {
			if typ != "none" && typ != "other" {
				content[typ] = map[string]any{"schema": map[string]any{}}
			}
		}
		item := map[string]any{"responses": map[string]any{"200": map[string]any{"description": "Observed backend success"}}, "parameters": parameters, "x-strata-observed-max-body-bytes": op.MaxBodyBytes}
		if len(content) > 0 {
			item["requestBody"] = map[string]any{"content": content}
		}
		paths[op.Path][strings.ToLower(op.Method)] = item
	}
	return json.Marshal(map[string]any{"openapi": "3.0.3", "info": map[string]any{"title": "API discovery documentation proposal", "version": "proposed"}, "x-strata-mode": "documentation_only", "paths": paths})
}
