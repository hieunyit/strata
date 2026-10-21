package localauth

import (
	"context"
	"crypto/subtle"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

type mfaState struct {
	enabled                bool
	seed, pending, session []byte
	until                  *time.Time
	request, etag          string
	last                   int64
	recovery               []string
}

func lockAccount(ctx context.Context, tx pgx.Tx, name, expectedHash string) error {
	var hash string
	var disabled, locked bool
	err := tx.QueryRow(ctx, `SELECT password_hash,disabled,COALESCE(locked_until>now(),false) FROM local_users WHERE username=$1 FOR UPDATE`, name).Scan(&hash, &disabled, &locked)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrBadCredentials
	}
	if err != nil {
		return err
	}
	if disabled || locked || (expectedHash != "" && hash != expectedHash) {
		return ErrBadCredentials
	}
	return nil
}

func loadMFA(ctx context.Context, tx pgx.Tx, name string) (mfaState, error) {
	var m mfaState
	err := tx.QueryRow(ctx, `SELECT enabled,seed,pending_seed,pending_session,pending_until,pending_request,etag,last_step,recovery_hashes FROM local_mfa WHERE username=$1 FOR UPDATE`, name).Scan(&m.enabled, &m.seed, &m.pending, &m.session, &m.until, &m.request, &m.etag, &m.last, &m.recovery)
	if errors.Is(err, pgx.ErrNoRows) {
		return m, nil
	}
	return m, err
}

// consumeMFA runs with the account and MFA rows locked. Its state change and
// session issuance must commit together; callers persist throttling on refusal.
func consumeMFA(ctx context.Context, tx pgx.Tx, name string, key []byte, code string, recovery bool, now time.Time) (bool, error) {
	m, err := loadMFA(ctx, tx, name)
	if err != nil || !m.enabled {
		return false, err
	}
	if code == "" {
		return false, ErrMFARequired
	}
	if len(code) > 64 {
		return false, ErrBadCredentials
	}
	if recovery {
		hash := recoveryHash(code)
		found := false
		for _, stored := range m.recovery {
			found = found || subtle.ConstantTimeCompare([]byte(hash), []byte(stored)) == 1
		}
		if !found {
			return false, ErrBadCredentials
		}
		_, err = tx.Exec(ctx, `UPDATE local_mfa SET recovery_hashes=array_remove(recovery_hashes,$2) WHERE username=$1`, name, hash)
		return true, err
	}
	seed, err := openSeed(key, m.seed, name)
	if err != nil {
		return false, err
	}
	step, ok := totpStep(seed, code, now, m.last)
	if !ok {
		return false, ErrBadCredentials
	}
	_, err = tx.Exec(ctx, `UPDATE local_mfa SET last_step=$2 WHERE username=$1`, name, step)
	return true, err
}

func failedMFATx(ctx context.Context, tx pgx.Tx, name string) error {
	_, err := tx.Exec(ctx, `UPDATE local_users SET failed_logins=failed_logins+1,locked_until=CASE WHEN failed_logins+1 >= $2 THEN now()+$3*interval '1 second' ELSE locked_until END WHERE username=$1`, name, MaxFailures, LockFor.Seconds())
	return err
}

func (s *Store) openSession(ctx context.Context, name, expectedHash string, tokenHash []byte, expires time.Time, ip, ua string, key []byte, code string, recovery bool, now time.Time) error {
	var refused error
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		if err := lockAccount(ctx, tx, name, expectedHash); err != nil {
			return err
		}
		verified, err := consumeMFA(ctx, tx, name, key, code, recovery, now)
		if err != nil {
			refused = err
			if errors.Is(err, ErrBadCredentials) {
				return failedMFATx(ctx, tx, name)
			}
			return nil
		}
		if _, err := tx.Exec(ctx, `UPDATE local_users SET failed_logins=0,locked_until=NULL,last_login_at=now() WHERE username=$1`, name); err != nil {
			return err
		}
		// Limit live sessions per account without letting old sessions survive indefinitely.
		if _, err := tx.Exec(ctx, `DELETE FROM local_sessions WHERE username=$1 AND (expires_at<=now() OR token_sha256 IN (SELECT token_sha256 FROM local_sessions WHERE username=$1 ORDER BY created_at DESC OFFSET 99))`, name); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO local_sessions(token_sha256,username,expires_at,client_ip,user_agent,mfa_verified) VALUES($1,$2,$3,$4,$5,$6)`, tokenHash, name, expires, ip, truncate(ua, 256), verified); err != nil {
			return err
		}
		return audit(ctx, tx, name, "local_sessions.start", name, nil, map[string]any{"client_ip": ip, "user_agent": truncate(ua, 256), "expires_at": expires.UTC(), "mfa": verified})
	})
	if err != nil {
		return err
	}
	return refused
}

// MFAStatus never includes enrollment material or recovery hashes.
type MFAStatus struct {
	Available         bool   `json:"available"`
	Enabled           bool   `json:"enabled"`
	Etag              string `json:"etag"`
	RecoveryRemaining int    `json:"recovery_remaining"`
}

func (s *Service) MFAStatus(ctx context.Context, name string) (MFAStatus, error) {
	out := MFAStatus{Available: len(s.mfaKey) == 32}
	err := s.store.pool.QueryRow(ctx, `SELECT enabled,etag,cardinality(recovery_hashes) FROM local_mfa WHERE username=$1`, name).Scan(&out.Enabled, &out.Etag, &out.RecoveryRemaining)
	if errors.Is(err, pgx.ErrNoRows) {
		err = nil
	}
	return out, err
}

type OwnSession struct {
	ID        string    `json:"id"`
	Etag      string    `json:"etag"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Current   bool      `json:"current"`
	MFA       bool      `json:"mfa_verified"`
}

func (s *Service) Sessions(ctx context.Context, name, token string) ([]OwnSession, error) {
	rows, err := s.store.pool.Query(ctx, `SELECT id::text,created_at,expires_at,token_sha256=$2,mfa_verified FROM local_sessions WHERE username=$1 AND expires_at>now() ORDER BY created_at DESC LIMIT 100`, name, hashToken(token))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []OwnSession{}
	for rows.Next() {
		var x OwnSession
		if err := rows.Scan(&x.ID, &x.CreatedAt, &x.ExpiresAt, &x.Current, &x.MFA); err != nil {
			return nil, err
		}
		x.Etag = x.ID
		out = append(out, x)
	}
	return out, rows.Err()
}

func (s *Service) RevokeSession(ctx context.Context, name, id, etag string) error {
	if len(id) != 36 || id != etag {
		return ErrMFAConflict
	}
	return s.store.inTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM local_sessions WHERE username=$1 AND id::text=$2`, name, id)
		if err != nil || tag.RowsAffected() == 0 {
			return err
		}
		return audit(ctx, tx, name, "local_sessions.revoke", name, nil, map[string]any{"session_id": id})
	})
}
