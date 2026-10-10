package api

import (
	"context"
	"net/http"
	"net/http/httptest"

	"github.com/strata/strata/control-plane/auth"
)

// tokenRoles authenticates the bearer token "<role>" as a caller with that
// role; any other token is refused.
type tokenRoles struct{}

func (tokenRoles) Authenticate(_ context.Context, raw string) (*auth.Principal, error) {
	for _, r := range auth.Roles {
		if raw == string(r) {
			return &auth.Principal{Subject: "user-" + raw, Roles: []auth.Role{r}}, nil
		}
	}
	return nil, auth.ErrUnauthenticated
}

// serve sends req as an operator unless it already carries a token.
func serve(s *Server, rec *httptest.ResponseRecorder, req *http.Request) {
	if req.Header.Get("Authorization") == "" {
		req.Header.Set("Authorization", "Bearer operator")
	}
	s.Handler().ServeHTTP(rec, req)
}
