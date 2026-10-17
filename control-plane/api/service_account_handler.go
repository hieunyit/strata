package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/strata/strata/control-plane/auth"
	"github.com/strata/strata/control-plane/store"
)

var validSAID = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{1,63}$`)

// AuditRecorder persists audit log entries.
type AuditRecorder interface {
	RecordAudit(ctx context.Context, a store.Audit) error
}

type CreateServiceAccountRequest struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Description string      `json:"description,omitempty"`
	Roles       []auth.Role `json:"roles"`
}

type CreateTokenRequest struct {
	Scopes     []auth.Permission `json:"scopes"`
	TTLSeconds int64             `json:"ttl_seconds"` // default 30 days if not set
}

type CreateTokenResponse struct {
	RawToken string                  `json:"raw_token"`
	Token    auth.ServiceAccountToken `json:"token"`
}

func writeSAError(w http.ResponseWriter, status int, msg string) {
	writeError(w, status, msg, "")
}

// RegisterServiceAccountRoutes registers service account management endpoints.
func RegisterServiceAccountRoutes(mux *http.ServeMux, saStore auth.ServiceAccountStore, audit ...AuditRecorder) {
	if saStore == nil {
		return
	}
	var auditor AuditRecorder
	if len(audit) > 0 {
		auditor = audit[0]
	}

	logAudit := func(ctx context.Context, caller *auth.Principal, action, resource string, before, after any) {
		if auditor == nil {
			return
		}
		actor := "system"
		subject := ""
		if caller != nil {
			if caller.Name != "" {
				actor = caller.Name
			} else if caller.Subject != "" {
				actor = caller.Subject
			}
			subject = caller.Subject
		}
		_ = auditor.RecordAudit(ctx, store.Audit{
			At:       time.Now().UTC(),
			Actor:    actor,
			Subject:  subject,
			Channel:  "api",
			Action:   action,
			Resource: resource,
			Before:   before,
			After:    after,
		})
	}

	// List or Create Service Accounts
	mux.HandleFunc("/v1/service-accounts", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			auth.RequireHTTP(auth.PermServiceAccountsRead, func(w http.ResponseWriter, r *http.Request) {
				list, err := saStore.ListServiceAccounts(r.Context())
				if err != nil {
					writeSAError(w, http.StatusInternalServerError, err.Error())
					return
				}
				if list == nil {
					list = []auth.ServiceAccount{}
				}
				writeJSON(w, http.StatusOK, map[string]any{"service_accounts": list})
			})(w, r)

		case http.MethodPost:
			auth.RequireHTTP(auth.PermServiceAccountsWrite, func(w http.ResponseWriter, r *http.Request) {
				var req CreateServiceAccountRequest
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					writeSAError(w, http.StatusBadRequest, "invalid request body")
					return
				}
				if strings.TrimSpace(req.Name) == "" {
					writeSAError(w, http.StatusBadRequest, "name is required")
					return
				}
				saID := strings.TrimSpace(req.ID)
				if saID == "" {
					saID = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(req.Name), " ", "-"))
				}
				if !validSAID.MatchString(saID) {
					writeSAError(w, http.StatusBadRequest, "invalid service account ID: must be 2-64 alphanumeric characters, dashes, or underscores")
					return
				}
				caller := auth.FromContext(r.Context())
				createdBy := "system"
				if caller != nil && caller.Name != "" {
					createdBy = caller.Name
				}
				created := auth.ServiceAccount{
					ID:          saID,
					Name:        req.Name,
					Description: req.Description,
					Roles:       req.Roles,
					CreatedAt:   time.Now().UTC(),
					CreatedBy:   createdBy,
				}
				if err := saStore.CreateServiceAccount(r.Context(), created); err != nil {
					writeSAError(w, http.StatusConflict, err.Error())
					return
				}
				logAudit(r.Context(), caller, "/v1/service-accounts:create", "service_accounts/"+created.ID, nil, created)
				writeJSON(w, http.StatusCreated, created)
			})(w, r)

		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})

	// Operations on /v1/service-accounts/{id} or /v1/service-accounts/{id}/tokens...
	mux.HandleFunc("/v1/service-accounts/", func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/v1/service-accounts/")
		parts := strings.Split(path, "/")
		if len(parts) == 0 || parts[0] == "" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		saID := parts[0]

		if len(parts) == 1 {
			// /v1/service-accounts/{id}
			switch r.Method {
			case http.MethodGet:
				auth.RequireHTTP(auth.PermServiceAccountsRead, func(w http.ResponseWriter, r *http.Request) {
					sa, err := saStore.GetServiceAccount(r.Context(), saID)
					if err != nil {
						if errors.Is(err, auth.ErrServiceAccountNotFound) {
							w.WriteHeader(http.StatusNotFound)
							return
						}
						writeSAError(w, http.StatusInternalServerError, err.Error())
						return
					}
					writeJSON(w, http.StatusOK, sa)
				})(w, r)

			case http.MethodDelete:
				auth.RequireHTTP(auth.PermServiceAccountsWrite, func(w http.ResponseWriter, r *http.Request) {
					caller := auth.FromContext(r.Context())
					existing, _ := saStore.GetServiceAccount(r.Context(), saID)
					if err := saStore.DeleteServiceAccount(r.Context(), saID); err != nil {
						writeSAError(w, http.StatusInternalServerError, err.Error())
						return
					}
					logAudit(r.Context(), caller, "/v1/service-accounts:delete", "service_accounts/"+saID, existing, nil)
					w.WriteHeader(http.StatusNoContent)
				})(w, r)

			default:
				w.WriteHeader(http.StatusMethodNotAllowed)
			}
			return
		}

		if len(parts) >= 2 && parts[1] == "tokens" {
			if len(parts) == 2 {
				// /v1/service-accounts/{id}/tokens
				switch r.Method {
				case http.MethodGet:
					auth.RequireHTTP(auth.PermServiceAccountsRead, func(w http.ResponseWriter, r *http.Request) {
						tokens, err := saStore.ListTokens(r.Context(), saID)
						if err != nil {
							writeSAError(w, http.StatusInternalServerError, err.Error())
							return
						}
						if tokens == nil {
							tokens = []auth.ServiceAccountToken{}
						}
						writeJSON(w, http.StatusOK, map[string]any{"tokens": tokens})
					})(w, r)

				case http.MethodPost:
					auth.RequireHTTP(auth.PermServiceAccountsWrite, func(w http.ResponseWriter, r *http.Request) {
						var req CreateTokenRequest
						if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
							writeSAError(w, http.StatusBadRequest, "invalid request body")
							return
						}
						ttl := time.Duration(req.TTLSeconds) * time.Second
						if req.TTLSeconds <= 0 {
							ttl = 30 * 24 * time.Hour // default 30 days
						}
						raw, tok, err := auth.GenerateToken(saID, req.Scopes, ttl)
						if err != nil {
							writeSAError(w, http.StatusBadRequest, err.Error())
							return
						}
						if err := saStore.CreateToken(r.Context(), tok); err != nil {
							writeSAError(w, http.StatusInternalServerError, err.Error())
							return
						}
						caller := auth.FromContext(r.Context())
						logAudit(r.Context(), caller, "/v1/service-accounts/tokens:create", "service_accounts/"+saID+"/tokens/"+tok.ID, nil, tok)
						writeJSON(w, http.StatusCreated, CreateTokenResponse{
							RawToken: raw,
							Token:    tok,
						})
					})(w, r)

				default:
					w.WriteHeader(http.StatusMethodNotAllowed)
				}
				return
			}

			if len(parts) == 3 && r.Method == http.MethodDelete {
				// /v1/service-accounts/{id}/tokens/{token_id}
				tokenID := parts[2]
				auth.RequireHTTP(auth.PermServiceAccountsWrite, func(w http.ResponseWriter, r *http.Request) {
					tokens, err := saStore.ListTokens(r.Context(), saID)
					if err != nil {
						writeSAError(w, http.StatusInternalServerError, err.Error())
						return
					}
					found := false
					for _, tok := range tokens {
						if tok.ID == tokenID {
							found = true
							break
						}
					}
					if !found {
						writeSAError(w, http.StatusNotFound, "token not found for this service account")
						return
					}
					if err := saStore.RevokeToken(r.Context(), tokenID); err != nil {
						writeSAError(w, http.StatusNotFound, "token not found")
						return
					}
					caller := auth.FromContext(r.Context())
					logAudit(r.Context(), caller, "/v1/service-accounts/tokens:revoke", "service_accounts/"+saID+"/tokens/"+tokenID, nil, map[string]string{"status": "revoked"})
					w.WriteHeader(http.StatusNoContent)
				})(w, r)
				return
			}
		}

		w.WriteHeader(http.StatusNotFound)
	})
}
