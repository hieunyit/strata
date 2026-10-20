package store

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
)

var ErrApplicationConflict = errors.New("store: application etag or request conflict")
var appID = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

type Application struct {
	ID           string                   `json:"id"`
	Name         string                   `json:"name"`
	Owner        string                   `json:"owner"`
	Etag         string                   `json:"etag"`
	Environments []ApplicationEnvironment `json:"environments"`
	Routes       []ApplicationRoute       `json:"routes"`
	CreatedAt    time.Time                `json:"created_at"`
	UpdatedAt    time.Time                `json:"updated_at"`
}
type ApplicationEnvironment struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	GroupID string `json:"group_id"`
}
type ApplicationRoute struct {
	ID            string `json:"id"`
	EnvironmentID string `json:"environment_id"`
	Host          string `json:"host"`
	PathPrefix    string `json:"path_prefix"`
	PolicyID      string `json:"policy_id"`
	SchemaID      string `json:"schema_id"`
}

type ApplicationBinding struct {
	RequestID     string  `json:"request_id,omitempty"`
	ID            int64   `json:"id"`
	Subject       string  `json:"subject"`
	Role          string  `json:"role"`
	ApplicationID *string `json:"application_id"`
	EnvironmentID *string `json:"environment_id"`
}

func (a *Application) Validate() error {
	if !appID.MatchString(a.ID) || strings.TrimSpace(a.Name) == "" || strings.TrimSpace(a.Owner) == "" || len(a.Name) > 128 || len(a.Owner) > 256 || !utf8.ValidString(a.Name+a.Owner) {
		return errors.New("application: invalid id, name or owner")
	}
	if len(a.Environments) > 32 || len(a.Routes) > 128 {
		return errors.New("application: too many environments or routes")
	}
	envs := map[string]bool{}
	routes := map[string]bool{}
	for _, e := range a.Environments {
		if !appID.MatchString(e.ID) || !appID.MatchString(e.GroupID) || e.Name == "" || len(e.Name) > 128 || envs[e.ID] {
			return errors.New("application: invalid or duplicate environment")
		}
		envs[e.ID] = true
	}
	for n, r := range a.Routes {
		if !appID.MatchString(r.ID) || routes[r.ID] || !envs[r.EnvironmentID] || len(r.Host) == 0 || len(r.Host) > 253 || strings.ContainsAny(r.Host, " /\\\r\n\t?#") || len(r.PathPrefix) == 0 || !strings.HasPrefix(r.PathPrefix, "/") || len(r.PathPrefix) > 1024 || strings.ContainsAny(r.PathPrefix, "\r\n\t?#") || len(r.PolicyID) == 0 || len(r.PolicyID) > 128 || len(r.SchemaID) > 128 {
			return errors.New("application: invalid or duplicate route")
		}
		a.Routes[n].Host = strings.ToLower(r.Host)
		routes[r.ID] = true
	}
	return nil
}

const applicationSelect = `SELECT a.id,a.name,a.owner,a.etag,a.created_at,a.updated_at,
 coalesce((SELECT jsonb_agg(jsonb_build_object('id',e.id,'name',e.name,'group_id',e.group_id) ORDER BY e.id) FROM application_environments e WHERE e.application_id=a.id),'[]'),
 coalesce((SELECT jsonb_agg(jsonb_build_object('id',r.id,'environment_id',r.environment_id,'host',r.host,'path_prefix',r.path_prefix,'policy_id',r.policy_id,'schema_id',r.schema_id) ORDER BY r.id) FROM application_routes r WHERE r.application_id=a.id),'[]') FROM applications a`

func scanApplication(row pgx.Row) (Application, error) {
	var a Application
	var envs, routes []byte
	err := row.Scan(&a.ID, &a.Name, &a.Owner, &a.Etag, &a.CreatedAt, &a.UpdatedAt, &envs, &routes)
	if errors.Is(err, pgx.ErrNoRows) {
		return a, ErrNotFound
	}
	if err != nil {
		return a, fmt.Errorf("store: application: %w", err)
	}
	if err = json.Unmarshal(envs, &a.Environments); err != nil {
		return a, err
	}
	err = json.Unmarshal(routes, &a.Routes)
	return a, err
}
func (s *Store) GetApplication(ctx context.Context, id string) (Application, error) {
	return scanApplication(s.pool.QueryRow(ctx, applicationSelect+" WHERE a.id=$1", id))
}
func (s *Store) ListApplications(ctx context.Context, ids []string, after string, limit int) ([]Application, error) {
	if limit < 1 || limit > 100 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, applicationSelect+" WHERE ($1::text[] IS NULL OR a.id=ANY($1)) AND a.id>$2 ORDER BY a.id LIMIT $3", ids, after, limit)
	if err != nil {
		return nil, fmt.Errorf("store: applications: %w", err)
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Application, error) { return scanApplication(r) })
}

func (s *Store) SaveApplication(ctx context.Context, a Application, create bool, requestID string, audit Audit) (Application, error) {
	if err := a.Validate(); err != nil {
		return Application{}, err
	}
	if len(requestID) > 128 {
		return Application{}, errors.New("application: request_id too long")
	}
	raw, err := json.Marshal(a)
	if err != nil {
		return a, err
	}
	digest := sha256.Sum256(raw)
	var before *Application
	err = s.inTx(ctx, func(tx pgx.Tx) error {
		// Serialize route ownership checks and retries across applications.
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", int64(0x5354524154410032)); err != nil {
			return err
		}
		action := "application.save:" + a.ID
		if requestID != "" {
			var before []byte
			var response []byte
			err := tx.QueryRow(ctx, "SELECT digest,response FROM application_write_requests WHERE subject=$1 AND request_id=$2 AND action=$3", audit.Subject, requestID, action).Scan(&before, &response)
			if err == nil {
				if string(before) != string(digest[:]) {
					return ErrApplicationConflict
				}
				return json.Unmarshal(response, &a)
			}
			if !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
		}
		if !create {
			prior, err := scanApplication(tx.QueryRow(ctx, applicationSelect+" WHERE a.id=$1 FOR UPDATE", a.ID))
			if err != nil {
				return err
			}
			before = &prior
		}
		tag, err := newEtag()
		if err != nil {
			return err
		}
		if create {
			err = tx.QueryRow(ctx, "INSERT INTO applications(id,name,owner,etag,created_by) VALUES($1,$2,$3,$4,$5) RETURNING created_at,updated_at", a.ID, a.Name, a.Owner, tag, audit.Actor).Scan(&a.CreatedAt, &a.UpdatedAt)
			if isUniqueViolation(err) {
				return ErrExists
			}
			if err != nil {
				return err
			}
		} else {
			err = tx.QueryRow(ctx, "UPDATE applications SET name=$2,owner=$3,etag=$4,updated_at=now() WHERE id=$1 AND etag=$5 RETURNING created_at,updated_at", a.ID, a.Name, a.Owner, tag, a.Etag).Scan(&a.CreatedAt, &a.UpdatedAt)
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrApplicationConflict
			}
			if err != nil {
				return err
			}
		}
		a.Etag = tag
		// Update environments in place so scoped bindings survive ordinary edits.
		keep := []string{}
		for _, e := range a.Environments {
			keep = append(keep, e.ID)
			if _, err = tx.Exec(ctx, `INSERT INTO application_environments(application_id,id,name,group_id) VALUES($1,$2,$3,$4) ON CONFLICT(application_id,id) DO UPDATE SET name=excluded.name,group_id=excluded.group_id`, a.ID, e.ID, e.Name, e.GroupID); err != nil {
				return err
			}
		}
		if _, err = tx.Exec(ctx, "DELETE FROM application_routes WHERE application_id=$1", a.ID); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, "DELETE FROM application_environments WHERE application_id=$1 AND NOT(id=ANY($2))", a.ID, keep); err != nil {
			return err
		}
		for _, r := range a.Routes {
			var conflict bool
			err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM application_routes r JOIN application_environments e ON (e.application_id,e.id)=(r.application_id,r.environment_id) WHERE (r.application_id<>$3 OR r.environment_id<>$4) AND r.host=$1 AND (starts_with(r.path_prefix,$2) OR starts_with($2,r.path_prefix)) AND e.group_id=(SELECT group_id FROM application_environments WHERE application_id=$3 AND id=$4))`, r.Host, r.PathPrefix, a.ID, r.EnvironmentID).Scan(&conflict)
			if err != nil {
				return err
			}
			if conflict {
				return errors.New("application: overlapping route ownership")
			}
			if _, err = tx.Exec(ctx, `INSERT INTO application_routes(application_id,environment_id,id,host,path_prefix,policy_id,schema_id) VALUES($1,$2,$3,$4,$5,$6,$7)`, a.ID, r.EnvironmentID, r.ID, r.Host, r.PathPrefix, r.PolicyID, r.SchemaID); err != nil {
				return err
			}
		}
		audit.Resource = "applications/" + a.ID
		audit.Before = before
		audit.After = a
		audit.RequestID = requestID
		if err = writeAudit(ctx, tx, audit); err != nil {
			return err
		}
		if requestID != "" {
			response, err := json.Marshal(a)
			if err != nil {
				return err
			}
			_, err = tx.Exec(ctx, "INSERT INTO application_write_requests(subject,request_id,action,digest,response) VALUES($1,$2,$3,$4,$5)", audit.Subject, requestID, action, digest[:], response)
			return err
		}
		return nil
	})
	if err != nil {
		return Application{}, fmt.Errorf("store: save application: %w", err)
	}
	return a, nil
}

func (s *Store) DeleteApplication(ctx context.Context, id, etag string, audit Audit) error {
	if etag == "" {
		return ErrApplicationConflict
	}
	return s.inTx(ctx, func(tx pgx.Tx) error {
		before, err := scanApplication(tx.QueryRow(ctx, applicationSelect+" WHERE a.id=$1 FOR UPDATE", id))
		if err != nil {
			return err
		}
		if before.Etag != etag {
			return ErrApplicationConflict
		}
		if _, err = tx.Exec(ctx, "DELETE FROM applications WHERE id=$1", id); err != nil {
			return err
		}
		audit.Resource = "applications/" + id
		audit.Before = before
		return writeAudit(ctx, tx, audit)
	})
}
