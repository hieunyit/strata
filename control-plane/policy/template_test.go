package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestAPITemplate_ValidationAndInheritance(t *testing.T) {
	// Find rules/templates/api.json relative to git repo root
	path := filepath.Join("..", "..", "rules", "templates", "api.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading api.json at %s: %v", path, err)
	}

	var tmpl Template
	if err := json.Unmarshal(data, &tmpl); err != nil {
		t.Fatalf("unmarshaling api.json: %v", err)
	}

	if tmpl.Name != "api" {
		t.Errorf("expected template name 'api', got %q", tmpl.Name)
	}

	// Validate the template spec itself
	if err := tmpl.Spec.Validate(); err != nil {
		t.Fatalf("template spec failed validation: %v", err)
	}

	// Test positive model defaults
	if tmpl.Spec.Mode != "enforce" {
		t.Errorf("expected mode enforce, got %s", tmpl.Spec.Mode)
	}
	if tmpl.Spec.Oversize != "block" {
		t.Errorf("expected oversize block for API template, got %s", tmpl.Spec.Oversize)
	}
	if tmpl.Spec.FailOnFindings != "block" {
		t.Errorf("expected fail_on_findings block, got %s", tmpl.Spec.FailOnFindings)
	}
	if tmpl.Spec.MaxArgs != 256 {
		t.Errorf("expected max_args 256, got %d", tmpl.Spec.MaxArgs)
	}
	if tmpl.Spec.MaxSnippetSize != 2048 {
		t.Errorf("expected max_snippet_size 2048, got %d", tmpl.Spec.MaxSnippetSize)
	}
	if tmpl.Spec.Privacy == nil || len(tmpl.Spec.Privacy.SensitiveFields) == 0 {
		t.Error("expected API template to define sensitive privacy fields")
	}
	if tmpl.Spec.Response == nil || !tmpl.Spec.Response.AllowedCodesCheck {
		t.Error("expected API template to enable allowed_codes_check")
	}

	// Test inheritance: empty policy inheriting from api template
	customPolicy := Spec{}
	customPolicy.InheritFrom(&tmpl)

	if err := customPolicy.Validate(); err != nil {
		t.Fatalf("inherited policy validation failed: %v", err)
	}

	if customPolicy.Mode != "enforce" || customPolicy.Oversize != "block" {
		t.Errorf("inherited policy fields mismatch: mode=%s, oversize=%s", customPolicy.Mode, customPolicy.Oversize)
	}

	// Test override: custom policy explicitly setting mode shadow should NOT be overwritten
	shadowPolicy := Spec{Mode: "shadow"}
	shadowPolicy.InheritFrom(&tmpl)
	if shadowPolicy.Mode != "shadow" {
		t.Errorf("expected custom mode shadow to be preserved, got %s", shadowPolicy.Mode)
	}
	if shadowPolicy.Oversize != "block" {
		t.Errorf("expected oversize block to be inherited, got %s", shadowPolicy.Oversize)
	}
}
