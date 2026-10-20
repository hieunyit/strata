package policy

import (
	"reflect"
	"slices"
	"testing"
)

// W20-S-01: every template is a valid spec that starts in shadow; a new
// policy starts from one, the request's fields on top, and records it.
func TestTemplates(t *testing.T) {
	if !reflect.DeepEqual(TemplateNames(), []string{"api", "base", "web"}) {
		t.Fatalf("templates %v", TemplateNames())
	}
	for name, tpl := range Templates {
		if err := tpl.Spec.Validate(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		if tpl.Spec.Mode != "shadow" || tpl.Name != name || tpl.Version < 1 || tpl.Description == "" {
			t.Errorf("%s: %+v", name, tpl)
		}
	}
	api, err := FromTemplate("api", Spec{})
	if err != nil {
		t.Fatal(err)
	}
	want := Templates["api"].Spec
	want.Template = &TemplateRef{Name: "api", Version: 1}
	if !reflect.DeepEqual(api, want) {
		t.Errorf("api\n%+v\nwant\n%+v", api, want)
	}
	if api.Oversize != "block" || api.MaxArgs != 256 || api.FailOnFindings != "block" || !api.Response.DBErrors ||
		!slices.Contains(api.Response.DataGuard, "jwt") || !slices.Contains(api.Privacy.SensitiveFields, "password") {
		t.Errorf("api template %+v", api)
	}
	// the request's fields win, the others stay the template's
	over, err := FromTemplate("api", Spec{Mode: "enforce", MaxArgs: 64, CRSPlugins: []string{"wordpress"}})
	if err != nil {
		t.Fatal(err)
	}
	if over.Mode != "enforce" || over.MaxArgs != 64 || over.Oversize != "block" || !reflect.DeepEqual(over.CRSPlugins, []string{"wordpress"}) {
		t.Errorf("over %+v", over)
	}
	if err := over.Validate(); err != nil {
		t.Error(err)
	}
	// a copy: changing the policy never changes the template
	over.Privacy.SensitiveFields[0] = "changed"
	over.Response.DataGuard[0] = "pan"
	if Templates["api"].Spec.Privacy.SensitiveFields[0] == "changed" || Templates["api"].Spec.Response.DataGuard[0] == "pan" {
		t.Error("template shares its lists with a policy")
	}
	if _, err := FromTemplate("nope", Spec{}); err == nil {
		t.Error("unknown template")
	}
	if err := (Spec{Mode: "shadow", Template: &TemplateRef{Name: "API!", Version: 1}}).Validate(); err == nil {
		t.Error("bad template reference")
	}
}
