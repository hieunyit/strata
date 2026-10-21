package setup

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"path/filepath"
)

const MFAKeyFile = "keys/local-mfa.key"

// MFAKey never regenerates an encryption key while enrolled accounts exist.
func MFAKey(dir string, inUse bool, r *Result) error {
	ok, err := exists(filepath.Join(dir, MFAKeyFile))
	if err != nil {
		return err
	}
	if ok {
		r.add(false, MFAKeyFile)
		return nil
	}
	if inUse {
		return errors.New("setup: local MFA encryption key is missing; restore it from encrypted backup")
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return err
	}
	if err := writeNew(filepath.Join(dir, MFAKeyFile), []byte(hex.EncodeToString(key)), 0o600); err != nil {
		return err
	}
	r.add(true, MFAKeyFile)
	return nil
}
