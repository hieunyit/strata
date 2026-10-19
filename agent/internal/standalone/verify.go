package standalone

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/strata/strata/agent/pkg/bundlefmt"
)

// VerifyBundle checks the signing key and signed header without activating it.
// As with fleet installation, the engine separately validates section layout.
func VerifyBundle(ctx context.Context, file, keyFile string) (bundlefmt.Header, error) {
	return verifyBundle(ctx, file, keyFile, "", false)
}

// VerifyBundlePolicy also requires a named signed policy without activating it.
// The engine still has to validate the remaining bundle layout.
func VerifyBundlePolicy(ctx context.Context, file, keyFile, policy string, enforce bool) (bundlefmt.Header, error) {
	if policy == "" {
		return bundlefmt.Header{}, errors.New("policy is required")
	}
	return verifyBundle(ctx, file, keyFile, policy, enforce)
}

func verifyBundle(ctx context.Context, file, keyFile, policy string, enforce bool) (bundlefmt.Header, error) {
	if err := ctx.Err(); err != nil {
		return bundlefmt.Header{}, err
	}
	key, err := readTrustedKeys(keyFile)
	if err != nil {
		return bundlefmt.Header{}, err
	}
	data, err := readBundleFile(file)
	if err != nil {
		return bundlefmt.Header{}, fmt.Errorf("read bundle: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return bundlefmt.Header{}, err
	}
	if policy != "" {
		return bundlefmt.VerifyPolicy(data, key, policy, enforce)
	}
	return bundlefmt.Verify(data, key)
}

func readTrustedKeys(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read trusted bundle keys: %w", err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 65))
	if err != nil {
		return nil, fmt.Errorf("read trusted bundle keys: %w", err)
	}
	if !bundlefmt.ValidKeys(b) {
		return nil, fmt.Errorf("trusted bundle keys must be 32 or 64 bytes")
	}
	return b, nil
}
