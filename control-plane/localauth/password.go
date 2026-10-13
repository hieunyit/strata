// Package localauth keeps console accounts in PostgreSQL (PO 2026-10-13): a
// username, an argon2id password hash and the admin roles, so a small
// installation can sign in without an OIDC provider. Sessions are random
// bearer tokens prefixed "stl_"; only their SHA-256 is stored.
package localauth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters: the OWASP minimum for argon2id (19 MiB, 2 passes,
// one lane), about 30 ms per hash on a 2 GHz core. Stored with each hash,
// so they can be raised later without breaking existing passwords.
const (
	argonMemory  = 19 * 1024
	argonTime    = 2
	argonThreads = 1
	argonKeyLen  = 32
	saltLen      = 16
)

// Password limits. The upper bound keeps one login from hashing megabytes.
const (
	MinPasswordLen = 12
	MaxPasswordLen = 256
)

// ErrWeakPassword is returned for a password outside the limits.
var ErrWeakPassword = fmt.Errorf("the password must be %d to %d characters", MinPasswordLen, MaxPasswordLen)

// CheckPassword enforces the length limits (counted in characters).
func CheckPassword(pw string) error {
	if n := utf8.RuneCountInString(pw); n < MinPasswordLen || len(pw) > MaxPasswordLen {
		return ErrWeakPassword
	}
	return nil
}

// HashPassword returns the PHC string of pw:
// $argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>.
func HashPassword(pw string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(pw), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	enc := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads, enc.EncodeToString(salt), enc.EncodeToString(key)), nil
}

var errBadHash = errors.New("localauth: malformed password hash")

// VerifyPassword reports whether pw matches the PHC string.
func VerifyPassword(phc, pw string) (bool, error) {
	parts := strings.Split(phc, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, errBadHash
	}
	var v int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &v); err != nil || v != argon2.Version {
		return false, errBadHash
	}
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil || m == 0 || m > 1<<20 || t == 0 || t > 16 || p == 0 {
		return false, errBadHash
	}
	enc := base64.RawStdEncoding
	salt, err := enc.DecodeString(parts[4])
	if err != nil {
		return false, errBadHash
	}
	want, err := enc.DecodeString(parts[5])
	if err != nil || len(want) == 0 || len(want) > 64 {
		return false, errBadHash
	}
	got := argon2.IDKey([]byte(pw), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}
