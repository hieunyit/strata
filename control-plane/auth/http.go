package auth

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
)

// Authenticator turns a raw bearer token into a caller.
type Authenticator interface {
	Authenticate(ctx context.Context, raw string) (*Principal, error)
}

// TokenFromRequest accepts credentials only in the Authorization header.
// URLs are logged and retained even for GET/HEAD; SSE clients must use fetch.
func TokenFromRequest(r *http.Request) string {
	return BearerToken(r.Header.Get("Authorization"))
}

// Middleware authenticates every request: without a valid bearer token it
// answers 401. Authorization is left to the routes (RequireHTTP) and to
// the gRPC interceptors behind the gateway.
func Middleware(a Authenticator, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, err := a.Authenticate(r.Context(), TokenFromRequest(r))
		if err != nil {
			if !errors.Is(err, ErrUnauthenticated) {
				log.Printf("[ERROR] auth: %v", err)
			}
			w.Header().Set("WWW-Authenticate", `Bearer realm="strata"`)
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		if p.Access != nil && !scopedHTTPPath(r.URL.Path) {
			writeError(w, http.StatusForbidden, "resource outside assigned scope")
			return
		}
		next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), p)))
	})
}

// RequireHTTP answers 403 unless the caller has perm.
func RequireHTTP(perm Permission, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !FromContext(r.Context()).Can(perm) {
			writeError(w, http.StatusForbidden, "permission denied: "+string(perm))
			return
		}
		next(w, r)
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": msg, "code": status})
}

// Dispatch sends a bearer token to the authenticator that issued it:
// tokens starting with ServiceAccountPrefix to ServiceAccount,
// tokens starting with LocalPrefix to Local (the control plane's own
// sessions), the others to OIDC. Either may be nil when not configured.
type Dispatch struct {
	LocalPrefix          string
	Local                Authenticator
	OIDC                 Authenticator
	ServiceAccountPrefix string
	ServiceAccount       Authenticator
}

func (d Dispatch) Authenticate(ctx context.Context, raw string) (*Principal, error) {
	if d.ServiceAccount != nil && d.ServiceAccountPrefix != "" && strings.HasPrefix(raw, d.ServiceAccountPrefix) {
		return d.ServiceAccount.Authenticate(ctx, raw)
	}
	if d.Local != nil && d.LocalPrefix != "" && strings.HasPrefix(raw, d.LocalPrefix) {
		return d.Local.Authenticate(ctx, raw)
	}
	if d.OIDC == nil {
		return nil, ErrUnauthenticated
	}
	return d.OIDC.Authenticate(ctx, raw)
}

func scopedHTTPPath(path string) bool {
	for _, prefix := range []string{"/v1/applications", "/v1/application-role-bindings", "/v1/events", "/v1/stats/", "/v1/policies", "/v1/nodes", "/v1/groups", "/v1/rollouts", "/v1/bundles", "/v1/operations", "/v1/commands", "/v1/auth/", "/v1/exceptions:fromBlockId", "/v1/version"} {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}
