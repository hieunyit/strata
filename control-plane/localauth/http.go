package localauth

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/strata/strata/control-plane/auth"
)

// Handler serves the local account API:
//
//	POST   /v1/auth/login       {username, password} → session   (no token)
//	POST   /v1/auth/logout      ends the caller's session
//	POST   /v1/auth/password    {current_password, new_password}  (local users)
//	GET    /v1/users            accounts                          (rolebindings:read)
//	POST   /v1/users            {username, password, roles}       (rolebindings:write)
//	PATCH  /v1/users/{name}     {roles?, disabled?, password?, unlock?}
//	DELETE /v1/users/{name}
type Handler struct {
	Service *Service
	Store   *Store
	// TrustedProxies may set X-Forwarded-For: the client IP used to
	// throttle logins is then the address the last of them saw. nil
	// trusts none.
	TrustedProxies *TrustedProxies
}

// Public registers the routes that take no token.
func (h *Handler) Public(mux *http.ServeMux) {
	mux.HandleFunc("/v1/auth/login", h.login)
}

// Authenticated registers the routes behind the auth middleware.
func (h *Handler) Authenticated(mux *http.ServeMux) {
	for _, path := range []string{"/v1/auth/mfa", "/v1/auth/mfa:begin", "/v1/auth/mfa:confirm", "/v1/auth/mfa:disable", "/v1/auth/mfa:recovery", "/v1/auth/sessions", "/v1/auth/sessions/"} {
		mux.HandleFunc(path, h.security)
	}
	mux.HandleFunc("/v1/auth/logout", h.logout)
	mux.HandleFunc("/v1/auth/password", h.changePassword)
	mux.HandleFunc("/v1/users", h.users)
	mux.HandleFunc("/v1/users/", h.user)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"error": msg, "code": status})
}

// fail maps the package's errors to HTTP answers.
func fail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrMFARequired):
		writeJSON(w, 401, map[string]any{"error": err.Error(), "code": 401, "reason": "MFA_REQUIRED"})
	case errors.Is(err, ErrMFAConflict):
		writeErr(w, 409, err.Error())
	case errors.Is(err, ErrMFAUnavailable):
		writeErr(w, 503, "local MFA unavailable")
	case errors.Is(err, ErrBadCredentials):
		writeErr(w, http.StatusUnauthorized, err.Error())
	case errors.Is(err, ErrThrottled):
		w.Header().Set("Retry-After", "300")
		writeErr(w, http.StatusTooManyRequests, err.Error())
	case errors.Is(err, ErrNotFound):
		writeErr(w, http.StatusNotFound, err.Error())
	case errors.Is(err, ErrExists), errors.Is(err, ErrLastAdmin):
		writeErr(w, http.StatusConflict, err.Error())
	case errors.Is(err, ErrWeakPassword), errors.Is(err, ErrBadUsername), errors.Is(err, ErrBadRoles):
		writeErr(w, http.StatusBadRequest, err.Error())
	default:
		log.Printf("[ERROR] local accounts: %v", err)
		writeErr(w, http.StatusInternalServerError, "internal server error")
	}
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json request body: "+err.Error())
		return false
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		writeErr(w, 400, "one JSON object required")
		return false
	}
	return true
}

func (h *Handler) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	if h.TrustedProxies.Contains(addr) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			if a, err := netip.ParseAddr(strings.TrimSpace(parts[len(parts)-1])); err == nil {
				return a.Unmap().String()
			}
		}
	}
	return addr.Unmap().String()
}

func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Code     string `json:"code"`
		Recovery bool   `json:"recovery"`
	}
	if !decode(w, r, &req) {
		return
	}
	s, err := h.Service.LoginMFA(r.Context(), req.Username, req.Password, req.Code, req.Recovery, h.clientIP(r), r.UserAgent())
	if err != nil {
		if errors.Is(err, ErrBadCredentials) {
			log.Print("[INFO] local sign-in refused")
		}
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, s)
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if tok := auth.BearerToken(r.Header.Get("Authorization")); strings.HasPrefix(tok, TokenPrefix) {
		if err := h.Service.Logout(r.Context(), tok); err != nil {
			fail(w, err)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) changePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	name := LocalUsername(auth.FromContext(r.Context()))
	if name == "" {
		writeErr(w, http.StatusBadRequest, "only local accounts have a password here; change an SSO password at the identity provider")
		return
	}
	var req struct {
		Current string `json:"current_password"`
		New     string `json:"new_password"`
	}
	if !decode(w, r, &req) {
		return
	}
	tok := auth.BearerToken(r.Header.Get("Authorization"))
	if err := h.Service.ChangeOwnPassword(r.Context(), name, req.Current, req.New, tok); err != nil {
		if errors.Is(err, ErrBadCredentials) {
			writeErr(w, http.StatusBadRequest, "the current password is wrong")
			return
		}
		fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) users(w http.ResponseWriter, r *http.Request) {
	p := auth.FromContext(r.Context())
	switch r.Method {
	case http.MethodGet:
		if !p.Can(auth.PermRoleBindingsRead) {
			writeErr(w, http.StatusForbidden, "permission denied: "+string(auth.PermRoleBindingsRead))
			return
		}
		list, err := h.Store.ListUsers(r.Context())
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"users": list})
	case http.MethodPost:
		if !p.Can(auth.PermRoleBindingsWrite) {
			writeErr(w, http.StatusForbidden, "permission denied: "+string(auth.PermRoleBindingsWrite))
			return
		}
		var req struct {
			Username string   `json:"username"`
			Password string   `json:"password"`
			Roles    []string `json:"roles"`
		}
		if !decode(w, r, &req) {
			return
		}
		name, err := NormalizeUsername(req.Username)
		if err != nil {
			fail(w, err)
			return
		}
		roles, err := CheckRoles(req.Roles)
		if err != nil {
			fail(w, err)
			return
		}
		if err := CheckPassword(req.Password); err != nil {
			fail(w, err)
			return
		}
		hash, err := HashPassword(req.Password)
		if err != nil {
			fail(w, err)
			return
		}
		u, err := h.Store.CreateUser(r.Context(), name, hash, roles, p.Name)
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"user": u})
	default:
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (h *Handler) user(w http.ResponseWriter, r *http.Request) {
	p := auth.FromContext(r.Context())
	name := strings.TrimPrefix(r.URL.Path, "/v1/users/")
	if name == "" || strings.Contains(name, "/") {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	perm := auth.PermRoleBindingsWrite
	if r.Method == http.MethodGet {
		perm = auth.PermRoleBindingsRead
	}
	if !p.Can(perm) {
		writeErr(w, http.StatusForbidden, "permission denied: "+string(perm))
		return
	}
	switch r.Method {
	case http.MethodGet:
		u, err := h.Store.GetUser(r.Context(), name)
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"user": u})
	case http.MethodPatch:
		var req struct {
			Roles    *[]string `json:"roles"`
			Disabled *bool     `json:"disabled"`
			Password *string   `json:"password"`
			Unlock   bool      `json:"unlock"`
		}
		if !decode(w, r, &req) {
			return
		}
		var patch Patch
		if req.Roles != nil {
			roles, err := CheckRoles(*req.Roles)
			if err != nil {
				fail(w, err)
				return
			}
			patch.Roles = &roles
		}
		patch.Disabled, patch.Unlock = req.Disabled, req.Unlock
		if req.Password != nil {
			if err := CheckPassword(*req.Password); err != nil {
				fail(w, err)
				return
			}
			hash, err := HashPassword(*req.Password)
			if err != nil {
				fail(w, err)
				return
			}
			patch.PasswordHash = &hash
		}
		u, err := h.Store.UpdateUser(r.Context(), name, patch, p.Name)
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"user": u})
	case http.MethodDelete:
		if err := h.Store.DeleteUser(r.Context(), name, p.Name); err != nil {
			fail(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}
