package localauth

import (
	"context"
	"crypto/subtle"
	"encoding/base32"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

type MFAEnrollment struct {
	Secret    string    `json:"secret"`
	URI       string    `json:"uri"`
	Etag      string    `json:"etag"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (s *Service) passwordProof(ctx context.Context, name, password string) (string, error) {
	if !s.ip.allow("mfa:"+name, time.Now()) {
		return "", ErrThrottled
	}
	c, err := s.store.credentials(ctx, name)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return "", ErrBadCredentials
		}
		return "", err
	}
	if len(password) > MaxPasswordLen {
		return "", ErrBadCredentials
	}
	ok, err := VerifyPassword(c.hash, password)
	if err != nil {
		return "", err
	}
	if c.disabled || c.lockedUntil != nil && c.lockedUntil.After(time.Now()) {
		return "", ErrBadCredentials
	}
	if !ok {
		if err := s.store.recordFailure(ctx, name, MaxFailures, LockFor); err != nil {
			return "", err
		}
		return "", ErrBadCredentials
	}
	return c.hash, nil
}

func liveOwnSession(ctx context.Context, tx pgx.Tx, name, token string) error {
	var live bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM local_sessions WHERE username=$1 AND token_sha256=$2 AND expires_at>now())`, name, hashToken(token)).Scan(&live)
	if err != nil {
		return err
	}
	if !live {
		return ErrBadCredentials
	}
	return nil
}

// BeginMFA is idempotent for one request and session during the ten-minute window.
func (s *Service) BeginMFA(ctx context.Context, name, password, token, request string) (MFAEnrollment, error) {
	var out MFAEnrollment
	if len(s.mfaKey) != 32 {
		return out, ErrMFAUnavailable
	}
	if request == "" || len(request) > 128 || strings.ContainsAny(request, "\x00\r\n") {
		return out, ErrMFAConflict
	}
	hash, err := s.passwordProof(ctx, name, password)
	if err != nil {
		return out, err
	}
	err = s.store.inTx(ctx, func(tx pgx.Tx) error {
		if err := lockAccount(ctx, tx, name, hash); err != nil {
			return err
		}
		if err := liveOwnSession(ctx, tx, name, token); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO local_mfa(username) VALUES($1) ON CONFLICT DO NOTHING`, name); err != nil {
			return err
		}
		m, err := loadMFA(ctx, tx, name)
		if err != nil {
			return err
		}
		if m.enabled {
			return ErrMFAConflict
		}
		var seed []byte
		if m.request == request && m.until != nil && m.until.After(s.now()) && subtle.ConstantTimeCompare(m.session, hashToken(token)) == 1 {
			seed, err = openSeed(s.mfaKey, m.pending, name)
			out.ExpiresAt = *m.until
		} else {
			seed, err = randomBytes(20)
			if err != nil {
				return err
			}
			sealed, e := sealSeed(s.mfaKey, seed, name)
			if e != nil {
				return e
			}
			out.ExpiresAt = s.now().Add(10 * time.Minute).UTC()
			err = tx.QueryRow(ctx, `UPDATE local_mfa SET pending_seed=$2,pending_session=$3,pending_until=$4,pending_request=$5,etag=gen_random_uuid()::text WHERE username=$1 RETURNING etag`, name, sealed, hashToken(token), out.ExpiresAt, request).Scan(&m.etag)
			if err == nil {
				err = audit(ctx, tx, name, "local_users.mfa_begin", name, nil, map[string]any{"expires_at": out.ExpiresAt})
			}
		}
		if err != nil {
			return err
		}
		out.Etag = m.etag
		out.Secret = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(seed)
		out.URI = "otpauth://totp/" + url.PathEscape("Strata:"+name) + "?" + url.Values{"secret": {out.Secret}, "issuer": {"Strata"}, "digits": {"6"}, "period": {"30"}, "algorithm": {"SHA1"}}.Encode()
		return nil
	})
	return out, err
}

func (s *Service) ConfirmMFA(ctx context.Context, name, token, etag, code string) ([]string, error) {
	var codes []string
	var refused error
	err := s.store.inTx(ctx, func(tx pgx.Tx) error {
		if err := lockAccount(ctx, tx, name, ""); err != nil {
			return err
		}
		if err := liveOwnSession(ctx, tx, name, token); err != nil {
			return err
		}
		m, err := loadMFA(ctx, tx, name)
		if err != nil {
			return err
		}
		if m.enabled || etag == "" || m.etag != etag || m.until == nil || !m.until.After(s.now()) || subtle.ConstantTimeCompare(m.session, hashToken(token)) != 1 {
			return ErrMFAConflict
		}
		seed, err := openSeed(s.mfaKey, m.pending, name)
		if err != nil {
			return err
		}
		step, ok := totpStep(seed, code, s.now(), -1)
		if !ok {
			refused = ErrBadCredentials
			return failedMFATx(ctx, tx, name)
		}
		var hashes []string
		codes, hashes, err = recoveryCodes()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE local_mfa SET enabled=true,seed=pending_seed,pending_seed=NULL,pending_session=NULL,pending_until=NULL,pending_request='',last_step=$2,recovery_hashes=$3,etag=gen_random_uuid()::text WHERE username=$1`, name, step, hashes); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM local_sessions WHERE username=$1 AND token_sha256<>$2`, name, hashToken(token)); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE local_sessions SET mfa_verified=true WHERE username=$1 AND token_sha256=$2`, name, hashToken(token)); err != nil {
			return err
		}
		return audit(ctx, tx, name, "local_users.mfa_enable", name, nil, map[string]any{"enabled": true, "recovery_remaining": len(hashes)})
	})
	if err != nil {
		return nil, err
	}
	return codes, refused
}

// ChangeMFA either disables MFA or replaces recovery codes, with fresh password
// and one-use MFA proof in the same transaction as session invalidation.
func (s *Service) ChangeMFA(ctx context.Context, name, password, token, etag, code string, recovery, disable bool) ([]string, error) {
	var codes []string
	hash, err := s.passwordProof(ctx, name, password)
	if err != nil {
		return nil, err
	}
	var refused error
	err = s.store.inTx(ctx, func(tx pgx.Tx) error {
		if err := lockAccount(ctx, tx, name, hash); err != nil {
			return err
		}
		if err := liveOwnSession(ctx, tx, name, token); err != nil {
			return err
		}
		m, err := loadMFA(ctx, tx, name)
		if err != nil {
			return err
		}
		if !m.enabled || etag == "" || m.etag != etag {
			return ErrMFAConflict
		}
		_, err = consumeMFA(ctx, tx, name, s.mfaKey, code, recovery, s.now())
		if err != nil {
			refused = err
			if errors.Is(err, ErrBadCredentials) {
				return failedMFATx(ctx, tx, name)
			}
			return nil
		}
		action := "local_users.mfa_recovery_rotate"
		if disable {
			_, err = tx.Exec(ctx, `DELETE FROM local_mfa WHERE username=$1`, name)
			action = "local_users.mfa_disable"
		} else {
			var hashes []string
			codes, hashes, err = recoveryCodes()
			if err == nil {
				_, err = tx.Exec(ctx, `UPDATE local_mfa SET recovery_hashes=$2,etag=gen_random_uuid()::text WHERE username=$1`, name, hashes)
			}
		}
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM local_sessions WHERE username=$1 AND token_sha256<>$2`, name, hashToken(token)); err != nil {
			return err
		}
		return audit(ctx, tx, name, action, name, nil, map[string]any{"enabled": !disable})
	})
	if err != nil {
		return nil, err
	}
	return codes, refused
}
