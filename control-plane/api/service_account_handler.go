package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/strata/strata/control-plane/auth"
)

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
func RegisterServiceAccountRoutes(mux *http.ServeMux, store auth.ServiceAccountStore) {
	if store == nil {
		return
	}

	// List or Create Service Accounts
	mux.HandleFunc("/v1/service-accounts", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			auth.RequireHTTP(auth.PermServiceAccountsRead, func(w http.ResponseWriter, r *http.Request) {
				list, err := store.ListServiceAccounts(r.Context())
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
				if strings.TrimSpace(req.ID) == "" || strings.TrimSpace(req.Name) == "" {
					writeSAError(w, http.StatusBadRequest, "id and name are required")
					return
				}
				caller := auth.FromContext(r.Context())
				created := auth.ServiceAccount{
					ID:          req.ID,
					Name:        req.Name,
					Description: req.Description,
					Roles:       req.Roles,
					CreatedAt:   time.Now().UTC(),
					CreatedBy:   caller.Name,
				}
				if err := store.CreateServiceAccount(r.Context(), created); err != nil {
					writeSAError(w, http.StatusConflict, err.Error())
					return
				}
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
					sa, err := store.GetServiceAccount(r.Context(), saID)
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
					if err := store.DeleteServiceAccount(r.Context(), saID); err != nil {
						writeSAError(w, http.StatusInternalServerError, err.Error())
						return
					}
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
						tokens, err := store.ListTokens(r.Context(), saID)
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
						if err := store.CreateToken(r.Context(), tok); err != nil {
							writeSAError(w, http.StatusInternalServerError, err.Error())
							return
						}
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
					if err := store.RevokeToken(r.Context(), tokenID); err != nil {
						writeSAError(w, http.StatusNotFound, "token not found")
						return
					}
					w.WriteHeader(http.StatusNoContent)
				})(w, r)
				return
			}
		}

		w.WriteHeader(http.StatusNotFound)
	})
}
