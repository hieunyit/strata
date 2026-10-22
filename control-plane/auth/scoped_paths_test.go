package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// RS-4b: an application-scoped principal reads the rule sets, as it reads
// the rule catalog (global metadata the policy editor needs); paths
// outside the scoped list stay refused.
func TestScopedPrincipalReadsRuleSets(t *testing.T) {
	h := Middleware(fixedAuth{"scoped": {Subject: "oidc:s", Roles: []Role{RoleOperator}, Access: &Access{}}},
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	for path, want := range map[string]int{
		"/v1/rule-sets":                     http.StatusOK,
		"/v1/rule-sets/bots-scanners/rules": http.StatusOK,
		"/v1/rule-sets:resolve":             http.StatusOK,
		"/v1/rule-catalog":                  http.StatusOK,
		"/v1/audit":                         http.StatusForbidden,
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer scoped")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Errorf("%s: %d, want %d", path, rec.Code, want)
		}
	}
}
