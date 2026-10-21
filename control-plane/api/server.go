package api

import (
	"context"
	"github.com/strata/strata/control-plane/health"
	"github.com/strata/strata/control-plane/investigation"
	"github.com/strata/strata/control-plane/policy"
	"github.com/strata/strata/control-plane/rulecat"
	"github.com/strata/strata/control-plane/ruleinventory"
	"net/http"
	"strings"
	"time"

	"github.com/strata/strata/control-plane/auth"
	"github.com/strata/strata/control-plane/ingest"
	"github.com/strata/strata/control-plane/localauth"
	"github.com/strata/strata/control-plane/store"
)

// AuditStore supplies recent audit log entries for GET /v1/audit.
type AuditStore interface {
	AuditEntries(ctx context.Context, limit int) ([]store.Audit, error)
}

// ServerConfig defines HTTP server configuration options.
type ServerConfig struct {
	RuleCatalog  *ruleinventory.Catalog
	Evidence     *investigation.Worker
	SystemHealth *health.Service
	Releases     *policy.Releases
	Applications *store.Store
	// ServiceAccounts is optional; only atomic durable writers enable mutations.
	ServiceAccounts auth.ServiceAccountStore

	// Annotations persists event classifications; nil disables writes.
	Annotations    EventAnnotationStore
	Exceptions     ExceptionPolicyStore
	ReplayKick     func()
	StagingNotices StagingNoticeReader
	Health         HealthReader // nil leaves the optional rule health route out

	Addr         string
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	// DeployTimeout replaces both for POST …:deploy, which compiles and
	// signs a bundle: with the whole signature package (9,000 rules) the
	// compile alone takes 10–20 s on a 2 GHz core. Default 3 min, above
	// the compiler's own limit (policy.Compiler.Timeout, 2 min).
	DeployTimeout time.Duration
	// Auth verifies bearer tokens; every route but /healthz requires one.
	Auth auth.Authenticator
	// Admin serves the other /v1/ routes (the grpc-gateway of
	// strata.admin.v1), which authorize in their gRPC interceptors.
	Admin http.Handler
	// Rules is the catalog of the compiled rules (decision trace metadata);
	// nil leaves it out.
	Rules *rulecat.Catalog
	// Local serves sign-in with local accounts and their administration;
	// nil when -local-auth is off.
	Local *localauth.Handler
	// Audit serves GET /v1/audit (recent audit_log entries); nil leaves it out.
	Audit AuditStore
	// OIDC tells the UI whether single sign-on is configured.
	OIDC bool
	// Ready reports the components for GET /readyz and whether the control
	// plane can serve (CP-A03); nil: always ready.
	Ready func(context.Context) (map[string]string, bool)
}

// AuthMethods is GET /v1/auth/methods: how the UI may sign in.
type AuthMethods struct {
	Local bool `json:"local"`
	OIDC  bool `json:"oidc"`
}

// Me is GET /v1/auth/me: the caller as the API sees it.
type Me struct {
	Scoped            bool                `json:"scoped"`
	PolicyPermissions map[string][]string `json:"policy_permissions,omitempty"`
	Sensitive         bool                `json:"sensitive"`
	Username          string              `json:"username"`
	Roles             []string            `json:"roles"`
	// Local: a local account (it can change its password here).
	Local bool `json:"local"`
}

// Server provides the REST API server for Strata control plane.
type Server struct {
	cfg        ServerConfig
	httpServer *http.Server
	handler    *EventHandler
	mux        *http.ServeMux
}

// NewServer initializes the HTTP router and server with middleware.
func NewServer(cfg ServerConfig, store ingest.EventStore) *Server {
	if cfg.Auth == nil {
		panic("api: ServerConfig.Auth is required")
	}
	if cfg.Addr == "" {
		cfg.Addr = ":8080"
	}
	if cfg.ReadTimeout <= 0 {
		cfg.ReadTimeout = 10 * time.Second
	}
	if cfg.WriteTimeout <= 0 {
		cfg.WriteTimeout = 10 * time.Second
	}
	if cfg.DeployTimeout <= 0 {
		cfg.DeployTimeout = 3 * time.Minute
	}

	eventHandler := NewEventHandler(store, cfg.Rules)
	eventHandler.authenticate = cfg.Auth
	eventHandler.annotations = cfg.Annotations
	mux := http.NewServeMux()

	s := &Server{
		cfg:     cfg,
		handler: eventHandler,
		mux:     mux,
	}

	s.registerRoutes()

	s.httpServer = &http.Server{
		Addr:         cfg.Addr,
		Handler:      s.withMiddleware(mux),
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
	}

	return s
}

// Handler returns the underlying http.Handler (useful for httptest).
func (s *Server) Handler() http.Handler {
	return s.withMiddleware(s.mux)
}

func (s *Server) registerRoutes() {
	v1 := http.NewServeMux()
	if s.cfg.Releases != nil {
		registerReleases(v1, s.cfg.Releases)
	}
	if s.cfg.SystemHealth != nil {
		v1.HandleFunc("/v1/health", auth.RequireHTTP(auth.PermNodesRead, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				w.WriteHeader(405)
				return
			}
			w.Header().Set("Cache-Control", "no-store")
			writeJSON(w, 200, s.cfg.SystemHealth.Collect(r.Context(), auth.FromContext(r.Context())))
		}))
	}
	if s.cfg.Applications != nil {
		registerApplications(v1, s.cfg.Applications, s.handler)
		s.registerInvestigation(v1)
	}
	if s.cfg.ServiceAccounts != nil {
		RegisterServiceAccountRoutes(v1, s.cfg.ServiceAccounts)
	}
	v1.HandleFunc("/v1/exceptions:fromBlockId", auth.RequireHTTP(auth.PermExceptionsWrite, s.HandleExceptionFromBlock))
	search := auth.RequireHTTP(auth.PermEventsRead, s.handler.HandleSearchEvents)
	v1.HandleFunc("/v1/events:search", search)
	// Handles /v1/events/{block_id}
	v1.HandleFunc("/v1/events/", auth.RequireHTTP(auth.PermEventsRead, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ":search") {
			search(w, r)
			return
		}
		if s.cfg.Applications != nil {
			switch {
			case strings.HasSuffix(r.URL.Path, ":case"):
				s.handleEventCase(w, r)
				return
			case strings.HasSuffix(r.URL.Path, ":propose-rule"):
				s.handleEventRule(w, r)
				return
			case strings.HasSuffix(r.URL.Path, ":similar"):
				s.handleSimilarEvents(w, r)
				return
			}
		}
		if strings.HasSuffix(r.URL.Path, ":markFalsePositive") {
			auth.RequireHTTP(auth.PermExceptionsWrite, s.handler.HandleMarkFalsePositive)(w, r)
			return
		}
		s.handler.HandleGetEvent(w, r)
	}))
	v1.HandleFunc("/v1/stats/overview", auth.RequireHTTP(auth.PermEventsRead, s.handler.HandleOverview))
	v1.HandleFunc("/v1/stats/geo", auth.RequireHTTP(auth.PermEventsRead, s.handler.HandleGeoStats))
	v1.HandleFunc("/v1/stats/geo:watch", auth.RequireHTTP(auth.PermEventsRead, s.handler.HandleGeoWatch))
	v1.HandleFunc("/v1/stats/timeline", auth.RequireHTTP(auth.PermEventsRead, s.handler.HandleTimeline))
	if s.cfg.StagingNotices != nil {
		v1.HandleFunc("/v1/rules/staging-actions", auth.RequireHTTP(auth.PermPoliciesApprove, s.handleStagingNotices))
	}
	if s.cfg.Health != nil {
		v1.HandleFunc("/v1/rules/", func(w http.ResponseWriter, r *http.Request) {
			if _, ok := healthPath(r.URL.Path); ok {
				auth.RequireHTTP(auth.PermEventsRead, s.handleRuleHealth)(w, r)
				return
			}
			if s.cfg.Admin != nil {
				s.cfg.Admin.ServeHTTP(w, r)
				return
			}
			http.NotFound(w, r)
		})
	}
	v1.HandleFunc("/v1/auth/me", func(w http.ResponseWriter, r *http.Request) {
		p := auth.FromContext(r.Context())
		roles := make([]string, len(p.Roles))
		for i, ro := range p.Roles {
			roles[i] = string(ro)
		}
		name := p.Name
		if name == "" {
			name = p.Subject
		}
		w.Header().Set("Cache-Control", "no-store")
		permissions := map[string][]string{}
		if p.Access != nil {
			for resource, perms := range p.Access.Resources {
				if strings.HasPrefix(resource, "policies/") {
					for perm, allowed := range perms {
						if allowed && p.Can(perm) {
							permissions[strings.TrimPrefix(resource, "policies/")] = append(permissions[strings.TrimPrefix(resource, "policies/")], string(perm))
						}
					}
				}
			}
		}
		writeJSON(w, http.StatusOK, Me{Scoped: p.Access != nil, Sensitive: p.Can(auth.PermEventsReadSensitive), PolicyPermissions: permissions, Username: name, Roles: roles, Local: localauth.LocalUsername(p) != ""})
	})
	if s.cfg.Audit != nil {
		v1.HandleFunc("/v1/audit", auth.RequireHTTP(auth.PermAuditRead, s.handleAudit))
	}
	if s.cfg.Local != nil {
		s.cfg.Local.Authenticated(v1)
		s.cfg.Local.Public(s.mux)
	}
	if s.cfg.Admin != nil {
		v1.Handle("/v1/", s.cfg.Admin)
	}
	s.mux.HandleFunc("/v1/auth/methods", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, AuthMethods{Local: s.cfg.Local != nil, OIDC: s.cfg.OIDC})
	})

	// Liveness for the container healthcheck; it reveals nothing.
	s.mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	// Readiness: component states only (ok, error, degraded, disabled),
	// no addresses or messages; 503 when the control plane cannot serve.
	s.mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.Ready == nil {
			writeJSON(w, http.StatusOK, map[string]any{"ready": true})
			return
		}
		parts, ready := s.cfg.Ready(r.Context())
		code := http.StatusOK
		if !ready {
			code = http.StatusServiceUnavailable
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, code, map[string]any{"ready": ready, "components": parts})
	})
	s.mux.Handle("/v1/", auth.Middleware(s.cfg.Auth, v1))
}

func (s *Server) withMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				writeError(w, http.StatusInternalServerError, "internal server error", "")
			}
		}()

		// Request timeout. A deploy gets longer, and so does its
		// connection: the server's read and write deadlines would otherwise
		// cancel the request (and kill the compiler) after ReadTimeout.
		timeout := s.cfg.WriteTimeout
		if isDeploy(r) {
			timeout = s.cfg.DeployTimeout
			rc := http.NewResponseController(w)
			deadline := time.Now().Add(timeout)
			_ = rc.SetReadDeadline(deadline)
			_ = rc.SetWriteDeadline(deadline)
		}
		if isStream(r) {
			// bounded by the handler (MaxGeoWatchDuration), not by the
			// request timeout
			next.ServeHTTP(w, r)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// isStream: GET /v1/stats/geo:watch, server-sent events.
func isStream(r *http.Request) bool {
	return r.Method == http.MethodGet && r.URL.Path == "/v1/stats/geo:watch"
}

// isDeploy includes release preparation and publication, which compile/sign artifacts.
func isDeploy(r *http.Request) bool {
	return r.Method == http.MethodPost && (r.URL.Path == "/v1/releases" || ((strings.HasPrefix(r.URL.Path, "/v1/policies/") || strings.HasPrefix(r.URL.Path, "/v1/releases/")) && strings.HasSuffix(r.URL.Path, ":deploy")))
}

// Start begins listening and serving HTTP requests.
func (s *Server) Start() error {
	return s.httpServer.ListenAndServe()
}

// Shutdown gracefully shuts down the server without interrupting active connections.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}
