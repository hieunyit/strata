package api

import (
	"github.com/strata/strata/control-plane/auth"
	"net/http"
)

func (s *Server) registerInvestigation(mux *http.ServeMux) {
	mux.HandleFunc("/v1/evidence", auth.RequireHTTP(auth.PermEventsRead, s.evidenceCollection))
	mux.HandleFunc("/v1/evidence/", auth.RequireHTTP(auth.PermEventsRead, s.evidenceItem))
	mux.HandleFunc("/v1/saved-searches", auth.RequireHTTP(auth.PermEventsRead, s.savedSearchCollection))
	mux.HandleFunc("/v1/saved-searches/", auth.RequireHTTP(auth.PermEventsRead, s.savedSearchItem))
}
