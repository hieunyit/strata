package localauth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" // RFC 4226/6238 interoperable HOTP, not a password hash.
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"
)

var (
	ErrMFARequired    = errors.New("a one-time or recovery code is required")
	ErrMFAUnavailable = errors.New("local MFA key is not configured")
	ErrMFAConflict    = errors.New("MFA configuration changed or enrollment expired")
)

// hotp follows RFC 4226 dynamic truncation; RFC 6238 uses a time counter.
func hotp(seed []byte, step int64, digits int) string {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(step))
	h := hmac.New(sha1.New, seed)
	_, _ = h.Write(b[:])
	sum := h.Sum(nil)
	off := sum[len(sum)-1] & 15
	n := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	mod := uint32(1)
	for range digits {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, n%mod)
}

func totpStep(seed []byte, code string, now time.Time, after int64) (int64, bool) {
	if len(code) != 6 {
		return 0, false
	}
	if _, err := strconv.ParseUint(code, 10, 32); err != nil {
		return 0, false
	}
	step := now.Unix() / 30
	matched := int64(-1)
	for _, candidate := range []int64{step - 1, step, step + 1} {
		if candidate >= 0 && candidate > after && subtle.ConstantTimeCompare([]byte(hotp(seed, candidate, 6)), []byte(code)) == 1 {
			matched = max(matched, candidate)
		}
	}
	return matched, matched >= 0
}

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return b, err
}

func sealSeed(key, seed []byte, username string) ([]byte, error) {
	if len(key) != 32 {
		return nil, ErrMFAUnavailable
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce, err := randomBytes(aead.NonceSize())
	if err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, seed, []byte("strata/local-mfa/v1/"+username)), nil
}

func openSeed(key, sealed []byte, username string) ([]byte, error) {
	if len(key) != 32 {
		return nil, ErrMFAUnavailable
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil || len(sealed) < aead.NonceSize()+aead.Overhead() {
		return nil, ErrMFAUnavailable
	}
	seed, err := aead.Open(nil, sealed[:aead.NonceSize()], sealed[aead.NonceSize():], []byte("strata/local-mfa/v1/"+username))
	if err != nil || len(seed) != 20 {
		return nil, ErrMFAUnavailable
	}
	return seed, nil
}

func recoveryHash(code string) string {
	sum := sha256.Sum256([]byte("strata/recovery/v1/" + code))
	return hex.EncodeToString(sum[:])
}

func recoveryCodes() ([]string, []string, error) {
	codes, hashes := []string{}, []string{}
	for range 8 {
		b, err := randomBytes(20)
		if err != nil {
			return nil, nil, err
		}
		code := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
		codes = append(codes, code)
		hashes = append(hashes, recoveryHash(code))
	}
	return codes, hashes, nil
}
