package store

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/strata/strata/control-plane/auth"
)

// MachineCommand binds one authenticated write to an immutable retry command.
// Input has only public command fields, never the generated plaintext secret.
type MachineCommand struct {
	RequestID, Etag string
	Input           any
}
type machineChange struct{ Receipt, Before, After any }

func (s *Store) machineMutation(ctx context.Context, cmd MachineCommand, action, resource string,
	apply func(pgx.Tx) (any, error)) ([]byte, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	p := auth.FromContext(ctx)
	if p == nil || p.Subject == "" || !p.Can(auth.PermServiceAccountsWrite) {
		return nil, false, auth.ErrUnauthenticated
	}
	if len(cmd.RequestID) < 1 || len(cmd.RequestID) > 128 || strings.ContainsRune(cmd.RequestID, 0) {
		return nil, false, fmt.Errorf("store: invalid machine request ID")
	}
	data, err := json.Marshal(struct {
		Action, Resource, Etag string
		Input                  any
	}{action, resource, cmd.Etag, cmd.Input})
	if err != nil {
		return nil, false, err
	}
	digest := sha256.Sum256(data)
	var receipt []byte
	replayed := false
	err = s.inTx(ctx, func(tx pgx.Tx) error {
		// Serialize retries without allocating a token or committing audit twice.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, p.Subject+"\x1f"+cmd.RequestID); err != nil {
			return err
		}
		var old []byte
		err := tx.QueryRow(ctx, `SELECT digest,receipt FROM machine_requests WHERE subject=$1 AND request_id=$2`, p.Subject, cmd.RequestID).Scan(&old, &receipt)
		if err == nil {
			if string(old) != string(digest[:]) {
				return ErrExists
			}
			replayed = true
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		result, err := apply(tx)
		if err != nil {
			return err
		}
		var before any
		after := result
		if change, ok := result.(machineChange); ok {
			result, before, after = change.Receipt, change.Before, change.After
		}
		receipt, err = json.Marshal(result)
		if err != nil {
			return err
		}
		actor := p.Name
		if actor == "" {
			actor = p.Subject
		}
		// Legacy audit_log has no subject column. Include immutable identity
		// in the machine audit state rather than relying on mutable display names.
		var auditBefore any
		if before != nil {
			auditBefore = map[string]any{"actor_subject": p.Subject, "state": before}
		}
		auditAfter := map[string]any{"actor_subject": p.Subject, "state": after}
		if err := writeAudit(ctx, tx, Audit{Actor: actor, Subject: p.Subject, Channel: "api", Action: action, Resource: resource, RequestID: cmd.RequestID, Before: auditBefore, After: auditAfter}); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO machine_requests(subject,request_id,digest,receipt) VALUES($1,$2,$3,$4)`, p.Subject, cmd.RequestID, digest[:], receipt)
		return err
	})
	if err != nil {
		return nil, false, fmt.Errorf("store: machine credential mutation: %w", err)
	}
	return receipt, replayed, nil
}

func (s *Store) CreateMachineAccount(ctx context.Context, sa auth.ServiceAccount, cmd MachineCommand) (auth.ServiceAccount, error) {
	data, _, err := s.machineMutation(ctx, cmd, "/v1/service-accounts:create", "service_accounts/"+sa.ID, func(tx pgx.Tx) (any, error) {
		sa.CreatedBy = auth.FromContext(ctx).Subject
		sa.CreatedAt = time.Now().UTC()
		sa.TokenCount = 0
		var err error
		sa.Etag, err = newEtag()
		if err != nil {
			return nil, err
		}
		metadata, err := json.Marshal(sa)
		if err != nil {
			return nil, err
		}
		_, err = tx.Exec(ctx, `INSERT INTO machine_accounts(id,metadata) VALUES($1,$2)`, sa.ID, metadata)
		if isUniqueViolation(err) {
			return nil, ErrExists
		}
		return sa, err
	})
	if err != nil {
		return sa, err
	}
	err = json.Unmarshal(data, &sa)
	return sa, err
}

func (s *Store) GetServiceAccount(ctx context.Context, id string) (*auth.ServiceAccount, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var data []byte
	var sa auth.ServiceAccount
	err := s.pool.QueryRow(ctx, `SELECT a.metadata,(SELECT count(*) FROM machine_tokens t WHERE t.account_id=a.id AND NOT t.revoked AND t.expires_at>now()) FROM machine_accounts a WHERE a.id=$1`, id).Scan(&data, &sa.TokenCount)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, auth.ErrServiceAccountNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: read machine account: %w", err)
	}
	count := sa.TokenCount
	if err = json.Unmarshal(data, &sa); err != nil {
		return nil, err
	}
	sa.TokenCount = count
	return &sa, nil
}

func (s *Store) ListServiceAccounts(ctx context.Context) ([]auth.ServiceAccount, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	rows, err := s.pool.Query(ctx, `SELECT a.metadata,(SELECT count(*) FROM machine_tokens t WHERE t.account_id=a.id AND NOT t.revoked AND t.expires_at>now()) FROM machine_accounts a ORDER BY a.id LIMIT 1001`)
	if err != nil {
		return nil, fmt.Errorf("store: list machine accounts: %w", err)
	}
	defer rows.Close()
	result := []auth.ServiceAccount{}
	for rows.Next() {
		var data []byte
		var sa auth.ServiceAccount
		var count int
		if err := rows.Scan(&data, &count); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(data, &sa); err != nil {
			return nil, err
		}
		sa.TokenCount = count
		result = append(result, sa)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(result) > 1000 {
		return nil, fmt.Errorf("store: machine account listing exceeds limit")
	}
	return result, nil
}

func (s *Store) IssueMachineToken(ctx context.Context, tok auth.ServiceAccountToken, cmd MachineCommand) (auth.ServiceAccountToken, bool, error) {

	data, replayed, err := s.machineMutation(ctx, cmd, "/v1/service-accounts/tokens:create", "service_accounts/"+tok.ServiceAccountID+"/tokens", func(tx pgx.Tx) (any, error) {
		if len(tok.Scopes) == 0 || len(tok.Scopes) > 32 || !time.Now().Before(tok.ExpiresAt) ||
			tok.CreatedAt.IsZero() || tok.ExpiresAt.Sub(tok.CreatedAt) > 365*24*time.Hour {
			return nil, auth.ErrInvalidToken
		}
		var account []byte
		err := tx.QueryRow(ctx, `SELECT metadata FROM machine_accounts WHERE id=$1 FOR UPDATE`, tok.ServiceAccountID).Scan(&account)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, auth.ErrServiceAccountNotFound
		}
		if err != nil {
			return nil, err
		}
		var sa auth.ServiceAccount
		if err := json.Unmarshal(account, &sa); err != nil {
			return nil, err
		}
		if cmd.Etag == "" || sa.Etag != cmd.Etag {
			return nil, ErrEtagMismatch
		}
		ceiling := &auth.Principal{Roles: sa.Roles}
		for _, scope := range tok.Scopes {
			if !ceiling.Can(scope) {
				return nil, auth.ErrInvalidToken
			}
		}
		var errEtag error
		tok.Etag, errEtag = newEtag()
		if errEtag != nil {
			return nil, errEtag
		}
		metadata, err := json.Marshal(tok)
		if err != nil {
			return nil, err
		}
		_, err = tx.Exec(ctx, `INSERT INTO machine_tokens(id,account_id,token_hash,metadata,expires_at) VALUES($1,$2,$3,$4,$5)`, tok.ID, tok.ServiceAccountID, tok.TokenHash, metadata, tok.ExpiresAt)
		return tok, err
	})
	if err != nil {
		return tok, false, err
	}
	err = json.Unmarshal(data, &tok)
	return tok, replayed, err
}

func (s *Store) DeleteMachineAccount(ctx context.Context, id string, cmd MachineCommand) error {
	_, _, err := s.machineMutation(ctx, cmd, "/v1/service-accounts:delete", "service_accounts/"+id, func(tx pgx.Tx) (any, error) {
		var data []byte
		err := tx.QueryRow(ctx, `SELECT metadata FROM machine_accounts WHERE id=$1 FOR UPDATE`, id).Scan(&data)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, auth.ErrServiceAccountNotFound
		}
		if err != nil {
			return nil, err
		}
		var sa auth.ServiceAccount
		if err := json.Unmarshal(data, &sa); err != nil {
			return nil, err
		}
		if cmd.Etag == "" || sa.Etag != cmd.Etag {
			return nil, ErrEtagMismatch
		}
		_, err = tx.Exec(ctx, `DELETE FROM machine_accounts WHERE id=$1`, id)
		return machineChange{Receipt: map[string]any{"deleted": sa.ID}, Before: sa}, err
	})
	return err
}

func (s *Store) RevokeMachineToken(ctx context.Context, account, id string, cmd MachineCommand) error {
	_, _, err := s.machineMutation(ctx, cmd, "/v1/service-accounts/tokens:revoke", "service_accounts/"+account+"/tokens/"+id, func(tx pgx.Tx) (any, error) {
		var data []byte
		err := tx.QueryRow(ctx, `SELECT metadata FROM machine_tokens WHERE id=$1 AND account_id=$2 FOR UPDATE`, id, account).Scan(&data)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, auth.ErrServiceAccountNotFound
		}
		if err != nil {
			return nil, err
		}
		var tok auth.ServiceAccountToken
		if err := json.Unmarshal(data, &tok); err != nil {
			return nil, err
		}
		if cmd.Etag == "" || tok.Etag != cmd.Etag {
			return nil, ErrEtagMismatch
		}
		before := tok
		now := time.Now().UTC()
		tok.Revoked = true
		tok.RevokedAt = &now
		tok.Etag, err = newEtag()
		if err != nil {
			return nil, err
		}
		encoded, err := json.Marshal(tok)
		if err != nil {
			return nil, err
		}
		_, err = tx.Exec(ctx, `UPDATE machine_tokens SET metadata=$1,revoked=true WHERE id=$2`, encoded, id)
		return machineChange{Receipt: map[string]any{"revoked": tok.ID}, Before: before, After: tok}, err
	})
	return err
}

func (s *Store) FindTokenByHash(ctx context.Context, hash string) (*auth.ServiceAccountToken, *auth.ServiceAccount, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var tokenData, accountData []byte
	var last *time.Time
	err := s.pool.QueryRow(ctx, `SELECT t.metadata,a.metadata,t.last_used_at FROM machine_tokens t JOIN machine_accounts a ON a.id=t.account_id WHERE t.token_hash=$1 AND NOT t.revoked AND t.expires_at>now()`, hash).Scan(&tokenData, &accountData, &last)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, auth.ErrServiceAccountNotFound
	}
	if err != nil {
		return nil, nil, fmt.Errorf("store: authenticate machine token: %w", err)
	}
	var tok auth.ServiceAccountToken
	var sa auth.ServiceAccount
	if err := json.Unmarshal(tokenData, &tok); err != nil {
		return nil, nil, err
	}
	if err := json.Unmarshal(accountData, &sa); err != nil {
		return nil, nil, err
	}
	tok.LastUsedAt = last
	return &tok, &sa, nil
}

func (s *Store) ListTokens(ctx context.Context, account string) ([]auth.ServiceAccountToken, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	rows, err := s.pool.Query(ctx, `SELECT metadata,last_used_at FROM machine_tokens WHERE account_id=$1 ORDER BY id LIMIT 1001`, account)
	if err != nil {
		return nil, fmt.Errorf("store: list machine tokens: %w", err)
	}
	defer rows.Close()
	result := []auth.ServiceAccountToken{}
	for rows.Next() {
		var data []byte
		var tok auth.ServiceAccountToken
		var last *time.Time
		if err := rows.Scan(&data, &last); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(data, &tok); err != nil {
			return nil, err
		}
		tok.LastUsedAt = last
		result = append(result, tok)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(result) > 1000 {
		return nil, fmt.Errorf("store: token listing exceeds limit")
	}
	return result, nil
}

func (s *Store) TouchTokenUsage(ctx context.Context, id string, at time.Time) error {
	tag, err := s.pool.Exec(ctx, `UPDATE machine_tokens SET last_used_at=$1 WHERE id=$2 AND NOT revoked AND expires_at>now()`, at, id)
	if err != nil {
		return fmt.Errorf("store: touch machine token: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return auth.ErrUnauthenticated
	}
	return nil
}
