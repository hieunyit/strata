package localauth

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/strata/strata/control-plane/auth"
)

// User is an account as the API shows it: never the hash.
type User struct {
	Username          string     `json:"username"`
	Roles             []string   `json:"roles"`
	Disabled          bool       `json:"disabled"`
	Locked            bool       `json:"locked"`
	CreatedAt         time.Time  `json:"created_at"`
	CreatedBy         string     `json:"created_by"`
	UpdatedAt         time.Time  `json:"updated_at"`
	PasswordChangedAt time.Time  `json:"password_changed_at"`
	LastLoginAt       *time.Time `json:"last_login_at,omitempty"`
}

var (
	ErrNotFound  = errors.New("no such user")
	ErrExists    = errors.New("the username is taken")
	ErrLastAdmin = errors.New("this would leave no enabled admin")
)

// Store is the PostgreSQL side of local accounts (tables local_users and
// local_sessions, migration 0007). Every change is written to audit_log in
// the same transaction.
type Store struct{ pool *pgxpool.Pool }

func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

const userCols = `username, roles, disabled, COALESCE(locked_until > now(), false), created_at, created_by,
	updated_at, password_changed_at, last_login_at`

func scanUser(row pgx.Row) (*User, error) {
	var u User
	if err := row.Scan(&u.Username, &u.Roles, &u.Disabled, &u.Locked, &u.CreatedAt, &u.CreatedBy,
		&u.UpdatedAt, &u.PasswordChangedAt, &u.LastLoginAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if u.Roles == nil {
		u.Roles = []string{}
	}
	return &u, nil
}

func (s *Store) inTx(ctx context.Context, f func(pgx.Tx) error) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := f(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func audit(ctx context.Context, tx pgx.Tx, actor, action, username string, before, after any) error {
	subject := ""
	if p := auth.FromContext(ctx); p != nil {
		subject = p.Subject
	} else if strings.HasPrefix(action, "local_sessions.") || action == "local_users.change_own_password" {
		// These internal paths already validated the local identity/session.
		subject = SubjectPrefix + username
	} else if strings.HasPrefix(actor, "system:") {
		subject = actor
	}
	enc := func(v any) ([]byte, error) {
		if v == nil {
			return nil, nil
		}
		return json.Marshal(v)
	}
	b, err := enc(before)
	if err != nil {
		return err
	}
	a, err := enc(after)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO audit_log (actor, subject, channel, action, resource, before, after)
		VALUES ($1, $2, 'api', $3, $4, $5, $6)`, actor, subject, action, "local_users/"+username, b, a)
	return err
}

// enabledAdmins counts the enabled accounts holding admin, other than skip.
func enabledAdmins(ctx context.Context, tx pgx.Tx, skip string) (int, error) {
	var n int
	err := tx.QueryRow(ctx, `SELECT count(*) FROM local_users WHERE NOT disabled AND 'admin' = ANY(roles) AND username <> $1`, skip).Scan(&n)
	return n, err
}

func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM local_users`).Scan(&n)
	return n, err
}

func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+userCols+` FROM local_users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []User{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *u)
	}
	return out, rows.Err()
}

func (s *Store) GetUser(ctx context.Context, username string) (*User, error) {
	return scanUser(s.pool.QueryRow(ctx, `SELECT `+userCols+` FROM local_users WHERE username = $1`, username))
}

// CreateUser stores a new account with an already hashed password.
func (s *Store) CreateUser(ctx context.Context, username, hash string, roles []string, actor string) (*User, error) {
	if roles == nil {
		roles = []string{}
	}
	var u *User
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		var err error
		u, err = scanUser(tx.QueryRow(ctx, `INSERT INTO local_users (username, password_hash, roles, created_by)
			VALUES ($1, $2, $3, $4) RETURNING `+userCols, username, hash, roles, actor))
		if err != nil {
			var pe *pgconn.PgError
			if errors.As(err, &pe) && pe.Code == "23505" {
				return ErrExists
			}
			return err
		}
		return audit(ctx, tx, actor, "local_users.create", username, nil, u)
	})
	return u, err
}

// Patch is a change to an account; nil fields stay as they are.
type Patch struct {
	Roles        *[]string
	Disabled     *bool
	PasswordHash *string
	// Unlock clears failed logins and the lock.
	Unlock bool
}

// UpdateUser applies p. A new password or disabling the account ends its
// sessions; demoting or disabling the last enabled admin is refused.
func (s *Store) UpdateUser(ctx context.Context, username string, p Patch, actor string) (*User, error) {
	var after *User
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		before, err := scanUser(tx.QueryRow(ctx, `SELECT `+userCols+` FROM local_users WHERE username = $1 FOR UPDATE`, username))
		if err != nil {
			return err
		}
		roles, disabled := before.Roles, before.Disabled
		if p.Roles != nil {
			roles = *p.Roles
		}
		if p.Disabled != nil {
			disabled = *p.Disabled
		}
		wasAdmin := !before.Disabled && contains(before.Roles, "admin")
		if wasAdmin && (disabled || !contains(roles, "admin")) {
			n, err := enabledAdmins(ctx, tx, username)
			if err != nil {
				return err
			}
			if n == 0 {
				return ErrLastAdmin
			}
		}
		q := `UPDATE local_users SET roles = $2, disabled = $3, updated_at = now()`
		args := []any{username, roles, disabled}
		if p.PasswordHash != nil {
			q += `, password_hash = $4, password_changed_at = now()`
			args = append(args, *p.PasswordHash)
		}
		if p.Unlock || p.PasswordHash != nil {
			q += `, failed_logins = 0, locked_until = NULL`
		}
		after, err = scanUser(tx.QueryRow(ctx, q+` WHERE username = $1 RETURNING `+userCols, args...))
		if err != nil {
			return err
		}
		if p.PasswordHash != nil || disabled {
			if _, err := tx.Exec(ctx, `DELETE FROM local_sessions WHERE username = $1`, username); err != nil {
				return err
			}
		}
		action := "local_users.update"
		if p.PasswordHash != nil {
			action = "local_users.set_password"
		}
		return audit(ctx, tx, actor, action, username, before, after)
	})
	return after, err
}

// DeleteUser removes the account and its sessions.
func (s *Store) DeleteUser(ctx context.Context, username, actor string) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		before, err := scanUser(tx.QueryRow(ctx, `SELECT `+userCols+` FROM local_users WHERE username = $1 FOR UPDATE`, username))
		if err != nil {
			return err
		}
		if !before.Disabled && contains(before.Roles, "admin") {
			n, err := enabledAdmins(ctx, tx, username)
			if err != nil {
				return err
			}
			if n == 0 {
				return ErrLastAdmin
			}
		}
		if _, err := tx.Exec(ctx, `DELETE FROM local_users WHERE username = $1`, username); err != nil {
			return err
		}
		return audit(ctx, tx, actor, "local_users.delete", username, before, nil)
	})
}

// credentials is what a login needs to know about an account.
type credentials struct {
	hash        string
	roles       []string
	disabled    bool
	lockedUntil *time.Time
}

func (s *Store) credentials(ctx context.Context, username string) (*credentials, error) {
	var c credentials
	err := s.pool.QueryRow(ctx, `SELECT password_hash, roles, disabled, locked_until FROM local_users WHERE username = $1`, username).
		Scan(&c.hash, &c.roles, &c.disabled, &c.lockedUntil)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &c, err
}

// recordFailure counts a wrong password; at maxFailures in a row the account
// is locked for lockFor.
func (s *Store) recordFailure(ctx context.Context, username string, maxFailures int, lockFor time.Duration) error {
	_, err := s.pool.Exec(ctx, `UPDATE local_users SET
			failed_logins = failed_logins + 1,
			locked_until = CASE WHEN failed_logins + 1 >= $2 THEN now() + $3 * interval '1 second' ELSE locked_until END
		WHERE username = $1`, username, maxFailures, lockFor.Seconds())
	return err
}

// startSession records a successful login and its session.
func (s *Store) startSession(ctx context.Context, username string, tokenHash []byte, expires time.Time, ip, ua string) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE local_users SET failed_logins = 0, locked_until = NULL, last_login_at = now() WHERE username = $1`, username); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO local_sessions (token_sha256, username, expires_at, client_ip, user_agent) VALUES ($1, $2, $3, $4, $5)`,
			tokenHash, username, expires, ip, truncate(ua, 256)); err != nil {
			return err
		}
		// who signed in, from where, until when; never the token
		return audit(ctx, tx, username, "local_sessions.start", username, nil, map[string]any{
			"client_ip": ip, "user_agent": truncate(ua, 256), "expires_at": expires.UTC(),
		})
	})
}

// sessionUser returns the account of a live session, nil when the session
// is unknown, expired, or its account disabled.
func (s *Store) sessionUser(ctx context.Context, tokenHash []byte) (username string, roles []string, err error) {
	err = s.pool.QueryRow(ctx, `SELECT u.username, u.roles FROM local_sessions s JOIN local_users u USING (username)
		WHERE s.token_sha256 = $1 AND s.expires_at > now() AND NOT u.disabled`, tokenHash).Scan(&username, &roles)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil, ErrNotFound
	}
	return username, roles, err
}

// endSession ends the session of tokenHash (a sign-out); an unknown or
// already ended session is not an error.
func (s *Store) endSession(ctx context.Context, tokenHash []byte) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		var username, ip string
		err := tx.QueryRow(ctx, `DELETE FROM local_sessions WHERE token_sha256 = $1 RETURNING username, client_ip`, tokenHash).
			Scan(&username, &ip)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		return audit(ctx, tx, username, "local_sessions.end", username, map[string]any{"client_ip": ip}, nil)
	})
}

// inTxSetPasswordKeeping sets the user's own new password and ends the
// user's sessions but keep.
func (s *Store) inTxSetPasswordKeeping(ctx context.Context, username, hash string, keep []byte) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE local_users SET password_hash = $2, password_changed_at = now(), updated_at = now(),
			failed_logins = 0, locked_until = NULL WHERE username = $1`, username, hash)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		if _, err := tx.Exec(ctx, `DELETE FROM local_sessions WHERE username = $1 AND token_sha256 <> $2`, username, keep); err != nil {
			return err
		}
		return audit(ctx, tx, username, "local_users.change_own_password", username, nil, nil)
	})
}

// DeleteExpired removes sessions past their expiry.
func (s *Store) DeleteExpired(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM local_sessions WHERE expires_at <= now()`)
	return tag.RowsAffected(), err
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "")
}
