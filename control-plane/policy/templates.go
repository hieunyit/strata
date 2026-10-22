package policy

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
)

// W20-S-01: policy templates (strata-overview.md › Mô hình policy: base,
// api, ...). A template is the starting point of a new policy: its spec is
// copied into the policy when the policy is created, with the fields the
// request sets on top, and the policy records the template's name and
// version. Afterwards the policy is on its own: a template change never
// reaches a running policy without a new version, replay and approval
// (PO decision 21/10/2026).

// TemplateRef records which template a policy started from.
type TemplateRef struct {
	Name    string `json:"name"`
	Version int    `json:"version"`
}

// Template is a named starting spec.
type Template struct {
	Name        string
	Version     int
	Description string
	Spec        Spec
}

// sensitiveAPIFields: names of API fields whose values never go into an
// event's snippet (privacy.sensitive_fields), on top of the built-in ones.
var sensitiveAPIFields = []string{"password", "passwd", "secret", "client_secret", "token", "access_token", "refresh_token", "api_key", "apikey", "otp"}

// botsLogged: every bot set of the catalog, logged (PO 22/10/2026: a new
// policy blocks no bot; the operator turns blocking on set by set).
var botsLogged = []RuleSetRef{
	{Set: "bots-scanners", Action: "log"},
	{Set: "bots-fake-crawlers", Action: "log"},
	{Set: "bots-http-libraries", Action: "log"},
	{Set: "bots-browser-automation", Action: "log"},
	{Set: "bots-ai-crawlers", Action: "log"},
	{Set: "bots-seo-advertising", Action: "log"},
	{Set: "bots-trusted", Action: "log"},
}

// with appends rule sets to the bots, without sharing the slice.
func with(sets ...RuleSetRef) []RuleSetRef {
	return append(append([]RuleSetRef(nil), botsLogged...), sets...)
}

// Templates by name. Every template starts in shadow: a new policy is
// observed before it blocks. Version 2 (RS-3): the rule sets are listed.
var Templates = map[string]Template{
	"base": {Name: "base", Version: 2,
		Description: "Defaults of the engine, in shadow: the protocol layer, the managed rules and the signature pack in shadow; every bot set logged.",
		Spec:        Spec{Mode: "shadow", RuleSets: with()}},
	"web": {Name: "web", Version: 2,
		Description: "Web site or application with forms and uploads: a body larger than what is inspected passes (uploads), database error messages in responses are reported; every bot set logged.",
		Spec:        Spec{Mode: "shadow", Oversize: "pass", Response: &Response{DBErrors: true}, RuleSets: with()}},
	"api": {Name: "api", Version: 2,
		Description: "JSON/REST API with an OpenAPI description: a body larger than what is inspected is blocked, at most 256 arguments are inspected (more go by oversize), " +
			"a CPU budget that runs out on a request with findings fails closed, database errors and JSON Web Tokens in responses are found (tokens masked when enforced), " +
			"credential fields (password, token, api_key, ...) never appear in events; every bot set logged.",
		Spec: Spec{Mode: "shadow", Oversize: "block", MaxArgs: 256, FailOnFindings: "block",
			Response: &Response{DBErrors: true, DataGuard: []string{"jwt"}},
			Privacy:  &Privacy{SensitiveFields: sensitiveAPIFields}, RuleSets: with()}},
	"strict": {Name: "strict", Version: 1,
		Description: "Stricter defaults for exposed applications: CRS paranoia level 2, a body larger than what is inspected is blocked, a CPU budget that runs out on a request with findings fails closed, " +
			"CVE virtual patches and the signatures of known exploited CVEs (CISA KEV) block; every bot set logged. Expect more false positives: observe it in shadow first.",
		Spec: Spec{Mode: "shadow", Oversize: "block", FailOnFindings: "block", CRSParanoia: 2,
			RuleSets: with(RuleSetRef{Set: "virtual-patches", Action: "block"}, RuleSetRef{Set: "signatures-kev", Action: "block"})}},
}

// TemplateNames in order.
func TemplateNames() []string { return slices.Sorted(maps.Keys(Templates)) }

// FromTemplate is the spec of a new policy made from template name: the
// template's spec, then every field over set in over on top (top-level
// fields, as the spec's JSON writes them), then the template reference.
// The result is not validated.
func FromTemplate(name string, over Spec) (Spec, error) {
	t, ok := Templates[name]
	if !ok {
		return Spec{}, fmt.Errorf("no template %q (one of %v)", name, TemplateNames())
	}
	base, err := json.Marshal(t.Spec)
	if err != nil {
		return Spec{}, err
	}
	top, err := json.Marshal(over)
	if err != nil {
		return Spec{}, err
	}
	var a, b map[string]json.RawMessage
	if err := json.Unmarshal(base, &a); err != nil {
		return Spec{}, err
	}
	if err := json.Unmarshal(top, &b); err != nil {
		return Spec{}, err
	}
	// mode is always written (no omitempty): an empty one is not a choice
	if string(b["mode"]) == `""` {
		delete(b, "mode")
	}
	maps.Copy(a, b)
	merged, err := json.Marshal(a)
	if err != nil {
		return Spec{}, err
	}
	var out Spec
	if err := json.Unmarshal(merged, &out); err != nil {
		return Spec{}, err
	}
	out.Template = &TemplateRef{Name: t.Name, Version: t.Version}
	return out, nil
}
