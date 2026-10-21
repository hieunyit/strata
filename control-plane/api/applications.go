package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/strata/strata/control-plane/auth"
	"github.com/strata/strata/control-plane/store"
)

func applicationAudit(r *http.Request) store.Audit {
	p := auth.FromContext(r.Context())
	return store.Audit{Actor: p.Name, Subject: p.Subject, Channel: "api", Action: r.Method + " " + r.URL.Path, RequestID: r.Header.Get("X-Request-ID")}
}
func applicationError(w http.ResponseWriter, err error) {
	status := http.StatusServiceUnavailable
	message := "application store unavailable"
	switch {
	case errors.Is(err, store.ErrNotFound):
		status = http.StatusNotFound
		message = "application not found"
	case errors.Is(err, store.ErrExists), errors.Is(err, store.ErrApplicationConflict):
		status = http.StatusConflict
		message = "application changed or request already exists"
	default:
		var pg *pgconn.PgError
		if errors.As(err, &pg) && pg.Code == "23503" {
			status = http.StatusBadRequest
			message = "unknown referenced resource"
		} else if strings.HasPrefix(err.Error(), "application:") || strings.HasPrefix(err.Error(), "binding:") {
			status = http.StatusBadRequest
			message = "invalid application request"
		} else if errors.As(err, &pg) {
			status = http.StatusInternalServerError
			message = "application operation failed"
		}
	}
	writeJSON(w, status, ErrorResponse{Error: message, Code: status})
}
func appBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		writeJSON(w, 400, ErrorResponse{Error: "invalid JSON", Code: 400})
		return false
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		writeJSON(w, 400, ErrorResponse{Error: "trailing JSON", Code: 400})
		return false
	}
	return true
}
func registerApplications(mux *http.ServeMux, st *store.Store, events *EventHandler) {
	mux.HandleFunc("/v1/applications", func(w http.ResponseWriter, r *http.Request) {
		p := auth.FromContext(r.Context())
		switch r.Method {
		case http.MethodGet:
			if !p.Can(auth.PermApplicationsRead) {
				writeJSON(w, 403, ErrorResponse{Error: "permission denied", Code: 403})
				return
			}
			var ids []string
			if p.Access != nil {
				ids = []string{}
				for id := range p.Access.Applications {
					ids = append(ids, id)
				}
			}
			limit := 100
			apps, err := st.ListApplications(r.Context(), ids, r.URL.Query().Get("after"), limit)
			if err != nil {
				applicationError(w, err)
				return
			}
			next := ""
			if len(apps) == limit {
				next = apps[len(apps)-1].ID
			}
			if apps == nil {
				apps = []store.Application{}
			}
			for i := range apps {
				apps[i] = visibleApplication(p, apps[i])
			}
			writeJSON(w, 200, map[string]any{"applications": apps, "next_cursor": next})
		case http.MethodPost:
			if !p.Can(auth.PermApplicationsWrite) {
				writeJSON(w, 403, ErrorResponse{Error: "permission denied", Code: 403})
				return
			}
			var req struct {
				Application store.Application `json:"application"`
				RequestID   string            `json:"request_id"`
			}
			if !appBody(w, r, &req) {
				return
			}
			out, err := st.SaveApplication(r.Context(), req.Application, true, req.RequestID, applicationAudit(r))
			if err != nil {
				applicationError(w, err)
				return
			}
			writeJSON(w, 201, map[string]any{"application": out})
		default:
			w.WriteHeader(405)
		}
	})
	mux.HandleFunc("/v1/applications/", func(w http.ResponseWriter, r *http.Request) {
		p := auth.FromContext(r.Context())
		id := strings.TrimPrefix(r.URL.Path, "/v1/applications/")
		if strings.HasSuffix(id, "/overview") {
			appID := strings.TrimSuffix(id, "/overview")
			ctx, err := st.ApplicationEventScope(r.Context(), appID, r.URL.Query().Get("environment_id"), p)
			if err != nil {
				applicationError(w, err)
				return
			}
			events.HandleOverview(w, r.WithContext(ctx))
			return
		}
		if strings.Contains(id, "/") || id == "" {
			http.NotFound(w, r)
			return
		}
		if !p.CanResource("applications/"+id, auth.PermApplicationsRead) {
			writeJSON(w, 404, ErrorResponse{Error: "application not found", Code: 404})
			return
		}
		switch r.Method {
		case http.MethodGet:
			out, err := st.GetApplication(r.Context(), id)
			if err != nil {
				applicationError(w, err)
				return
			}
			writeJSON(w, 200, map[string]any{"application": visibleApplication(p, out)})
		case http.MethodPut:
			if !p.Can(auth.PermApplicationsWrite) {
				writeJSON(w, 403, ErrorResponse{Error: "permission denied", Code: 403})
				return
			}
			var req struct {
				Application store.Application `json:"application"`
				RequestID   string            `json:"request_id"`
			}
			if !appBody(w, r, &req) {
				return
			}
			if req.Application.ID != id {
				writeJSON(w, 400, ErrorResponse{Error: "application id mismatch", Code: 400})
				return
			}
			out, err := st.SaveApplication(r.Context(), req.Application, false, req.RequestID, applicationAudit(r))
			if err != nil {
				applicationError(w, err)
				return
			}
			writeJSON(w, 200, map[string]any{"application": visibleApplication(p, out)})
		case http.MethodDelete:
			if !p.Can(auth.PermApplicationsWrite) {
				writeJSON(w, 403, ErrorResponse{Error: "permission denied", Code: 403})
				return
			}
			if err := st.DeleteApplication(r.Context(), id, r.Header.Get("If-Match"), applicationAudit(r)); err != nil {
				applicationError(w, err)
				return
			}
			w.WriteHeader(204)
		default:
			w.WriteHeader(405)
		}
	})
	mux.HandleFunc("/v1/application-role-bindings", func(w http.ResponseWriter, r *http.Request) {
		p := auth.FromContext(r.Context())
		if r.Method == http.MethodGet {
			if !p.Can(auth.PermRoleBindingsRead) {
				writeJSON(w, 403, ErrorResponse{Error: "permission denied", Code: 403})
				return
			}
			bs, err := st.ApplicationBindings(r.Context())
			if err != nil {
				applicationError(w, err)
				return
			}
			if bs == nil {
				bs = []store.ApplicationBinding{}
			}
			writeJSON(w, 200, map[string]any{"bindings": bs})
			return
		}
		if r.Method != http.MethodPost {
			w.WriteHeader(405)
			return
		}
		if !p.Can(auth.PermRoleBindingsWrite) {
			writeJSON(w, 403, ErrorResponse{Error: "permission denied", Code: 403})
			return
		}
		var req struct {
			Binding store.ApplicationBinding `json:"binding"`
		}
		if !appBody(w, r, &req) {
			return
		}
		b, err := st.AddApplicationBinding(r.Context(), req.Binding, applicationAudit(r))
		if err != nil {
			applicationError(w, err)
			return
		}
		writeJSON(w, 201, map[string]any{"binding": b})
	})
	mux.HandleFunc("/v1/application-role-bindings/", func(w http.ResponseWriter, r *http.Request) {
		p := auth.FromContext(r.Context())
		if !p.Can(auth.PermRoleBindingsWrite) {
			writeJSON(w, 403, ErrorResponse{Error: "permission denied", Code: 403})
			return
		}
		if r.Method != http.MethodDelete {
			w.WriteHeader(405)
			return
		}
		id, err := strconv.ParseInt(strings.TrimPrefix(r.URL.Path, "/v1/application-role-bindings/"), 10, 64)
		if err != nil || id < 1 {
			writeJSON(w, 400, ErrorResponse{Error: "invalid binding id", Code: 400})
			return
		}
		if err := st.DeleteApplicationBinding(r.Context(), id, applicationAudit(r)); err != nil {
			applicationError(w, err)
			return
		}
		w.WriteHeader(204)
	})
}

// Environment bindings must not disclose other environments' route metadata.
func visibleApplication(p *auth.Principal, a store.Application) store.Application {
	if p.Access == nil || p.Access.Environments[a.ID+"/*"] {
		return a
	}
	envs := []store.ApplicationEnvironment{}
	routes := []store.ApplicationRoute{}
	for _, e := range a.Environments {
		if p.Access.Environments[a.ID+"/"+e.ID] {
			envs = append(envs, e)
		}
	}
	for _, route := range a.Routes {
		if p.Access.Environments[a.ID+"/"+route.EnvironmentID] {
			routes = append(routes, route)
		}
	}
	a.Environments, a.Routes = envs, routes
	return a
}
