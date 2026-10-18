package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/strata/strata/control-plane/auth"
	"github.com/strata/strata/control-plane/store"
)

var validSAID = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{1,63}$`)

type CreateServiceAccountRequest struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Description string      `json:"description,omitempty"`
	Roles       []auth.Role `json:"roles"`
	RequestID   string      `json:"request_id"`
}
type CreateTokenRequest struct {
	Scopes     []auth.Permission `json:"scopes"`
	TTLSeconds int64             `json:"ttl_seconds"`
	RequestID  string            `json:"request_id"`
	Etag       string            `json:"etag"`
}
type CreateTokenResponse struct {
	RawToken string                   `json:"raw_token,omitempty"`
	Token    auth.ServiceAccountToken `json:"token"`
	Replayed bool                     `json:"replayed,omitempty"`
}

// Writes must atomically persist the credential, receipt and audit. A memory
// authenticator may be used by tests, but cannot enable unaudited API mutations.
type machineWriter interface {
	CreateMachineAccount(context.Context, auth.ServiceAccount, store.MachineCommand) (auth.ServiceAccount, error)
	IssueMachineToken(context.Context, auth.ServiceAccountToken, store.MachineCommand) (auth.ServiceAccountToken, bool, error)
	DeleteMachineAccount(context.Context, string, store.MachineCommand) error
	RevokeMachineToken(context.Context, string, string, store.MachineCommand) error
}

func writeSAError(w http.ResponseWriter, status int, message string) {
	writeError(w, status, message, "")
}
func machineError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, auth.ErrInvalidToken):
		writeSAError(w, 400, "invalid token fields or scope ceiling")
	case errors.Is(err, auth.ErrServiceAccountNotFound):
		writeSAError(w, 404, "service account or token not found")
	case errors.Is(err, store.ErrExists):
		writeSAError(w, 409, "resource or request ID conflicts")
	case errors.Is(err, store.ErrEtagMismatch):
		writeSAError(w, 409, "etag does not match; reload before retrying")
	default:
		writeSAError(w, 500, "service account operation failed")
	}
}
func validMachineCommand(c store.MachineCommand, etag bool) bool {
	if len(c.RequestID) == 0 || len(c.RequestID) > 128 || !utf8.ValidString(c.RequestID) || strings.ContainsRune(c.RequestID, 0) {
		return false
	}
	if !etag {
		return true
	}
	return len(c.Etag) > 0 && len(c.Etag) <= 128 && utf8.ValidString(c.Etag) && !strings.ContainsRune(c.Etag, 0)
}

func RegisterServiceAccountRoutes(mux *http.ServeMux, saStore auth.ServiceAccountStore) {
	if saStore == nil {
		return
	}
	writer, canWrite := saStore.(machineWriter)
	writeReady := func(w http.ResponseWriter) bool {
		if !canWrite {
			writeSAError(w, 503, "durable credential writes unavailable")
		}
		return canWrite
	}
	mux.HandleFunc("/v1/service-accounts", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		switch r.Method {
		case http.MethodGet:
			auth.RequireHTTP(auth.PermServiceAccountsRead, func(w http.ResponseWriter, r *http.Request) {
				list, err := saStore.ListServiceAccounts(r.Context())
				if err != nil {
					machineError(w, err)
					return
				}
				if list == nil {
					list = []auth.ServiceAccount{}
				}
				writeJSON(w, 200, map[string]any{"service_accounts": list})
			})(w, r)
		case http.MethodPost:
			auth.RequireHTTP(auth.PermServiceAccountsWrite, func(w http.ResponseWriter, r *http.Request) {
				var req CreateServiceAccountRequest
				if err := decodeSACommand(w, r, &req); err != nil {
					writeSAError(w, 400, "invalid request body")
					return
				}
				req.Name = strings.TrimSpace(req.Name)
				req.ID = strings.TrimSpace(req.ID)
				if req.ID == "" {
					req.ID = strings.ToLower(strings.ReplaceAll(req.Name, " ", "-"))
				}
				if !validSAID.MatchString(req.ID) || len(req.Name) == 0 || len(req.Name) > 128 || len(req.Description) > 2048 || strings.ContainsRune(req.Name+req.Description, 0) {
					writeSAError(w, 400, "invalid account fields")
					return
				}
				if len(req.Roles) == 0 {
					req.Roles = []auth.Role{auth.RoleViewer}
				}
				if len(req.Roles) > 4 {
					writeSAError(w, 400, "too many roles")
					return
				}
				for _, role := range req.Roles {
					if len(auth.ParseRoles([]string{string(role)})) != 1 {
						writeSAError(w, 400, "unknown service account role")
						return
					}
				}
				command := store.MachineCommand{RequestID: req.RequestID, Input: req}
				if !validMachineCommand(command, false) {
					writeSAError(w, 400, "request_id is required (1-128 characters)")
					return
				}
				if !writeReady(w) {
					return
				}
				caller := auth.FromContext(r.Context())
				created, err := writer.CreateMachineAccount(r.Context(), auth.ServiceAccount{ID: req.ID, Name: req.Name, Description: req.Description, Roles: req.Roles, CreatedAt: time.Now().UTC(), CreatedBy: caller.Subject}, command)
				if err != nil {
					machineError(w, err)
					return
				}
				writeJSON(w, 201, created)
			})(w, r)
		default:
			w.WriteHeader(405)
		}
	})
	mux.HandleFunc("/v1/service-accounts/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/service-accounts/"), "/")
		if len(parts) == 0 || !validSAID.MatchString(parts[0]) {
			http.NotFound(w, r)
			return
		}
		id := parts[0]
		if len(parts) == 1 && r.Method == http.MethodGet {
			auth.RequireHTTP(auth.PermServiceAccountsRead, func(w http.ResponseWriter, r *http.Request) {
				sa, err := saStore.GetServiceAccount(r.Context(), id)
				if err != nil {
					machineError(w, err)
					return
				}
				writeJSON(w, 200, sa)
			})(w, r)
			return
		}
		if len(parts) == 2 && parts[1] == "tokens" {
			switch r.Method {
			case http.MethodGet:
				auth.RequireHTTP(auth.PermServiceAccountsRead, func(w http.ResponseWriter, r *http.Request) {
					if _, err := saStore.GetServiceAccount(r.Context(), id); err != nil {
						machineError(w, err)
						return
					}
					tokens, err := saStore.ListTokens(r.Context(), id)
					if err != nil {
						machineError(w, err)
						return
					}
					if tokens == nil {
						tokens = []auth.ServiceAccountToken{}
					}
					writeJSON(w, 200, map[string]any{"tokens": tokens})
				})(w, r)
			case http.MethodPost:
				auth.RequireHTTP(auth.PermServiceAccountsWrite, func(w http.ResponseWriter, r *http.Request) {
					var req CreateTokenRequest
					if err := decodeSACommand(w, r, &req); err != nil {
						writeSAError(w, 400, "invalid request body")
						return
					}
					if req.TTLSeconds < 0 || req.TTLSeconds > 31536000 {
						writeSAError(w, 400, "ttl_seconds must be 0-31536000")
						return
					}
					command := store.MachineCommand{RequestID: req.RequestID, Etag: req.Etag, Input: req}
					if !validMachineCommand(command, true) {
						writeSAError(w, 400, "request_id and account etag are required")
						return
					}
					ttl := time.Duration(req.TTLSeconds) * time.Second
					if ttl == 0 {
						ttl = 30 * 24 * time.Hour
					}
					raw, tok, err := auth.GenerateToken(id, req.Scopes, ttl)
					if err != nil {
						writeSAError(w, 400, "invalid token scopes or TTL")
						return
					}
					if !writeReady(w) {
						return
					}
					tok, replayed, err := writer.IssueMachineToken(r.Context(), tok, command)
					if err != nil {
						machineError(w, err)
						return
					}
					status := 201
					if replayed {
						status = 200
						raw = ""
					}
					writeJSON(w, status, CreateTokenResponse{RawToken: raw, Token: tok, Replayed: replayed})
				})(w, r)
			default:
				w.WriteHeader(405)
			}
			return
		}
		if (len(parts) == 1 || len(parts) == 3 && parts[1] == "tokens" && parts[2] != "") && r.Method == http.MethodDelete {
			auth.RequireHTTP(auth.PermServiceAccountsWrite, func(w http.ResponseWriter, r *http.Request) {
				if len(parts) == 3 && (len(parts[2]) > 128 || !utf8.ValidString(parts[2]) || strings.ContainsRune(parts[2], 0)) {
					writeSAError(w, 400, "invalid token identifier")
					return
				}
				command := store.MachineCommand{RequestID: r.Header.Get("Idempotency-Key"), Etag: strings.Trim(r.Header.Get("If-Match"), "\"")}
				if !validMachineCommand(command, true) {
					writeSAError(w, 400, "Idempotency-Key and If-Match are required")
					return
				}
				if !writeReady(w) {
					return
				}
				var err error
				if len(parts) == 1 {
					err = writer.DeleteMachineAccount(r.Context(), id, command)
				} else {
					err = writer.RevokeMachineToken(r.Context(), id, parts[2], command)
				}
				if err != nil {
					machineError(w, err)
					return
				}
				w.WriteHeader(204)
			})(w, r)
			return
		}
		w.WriteHeader(405)
	})
}

func decodeSACommand(w http.ResponseWriter, r *http.Request, value any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("expected exactly one JSON value")
	}
	return nil
}
