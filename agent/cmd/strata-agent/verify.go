package main

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/strata/strata/agent/internal/standalone"
)

func newVerifyBundleCmd() *cobra.Command {
	var file, key string
	cmd := &cobra.Command{
		Use: "verify-bundle", Short: "Verify a bundle signature without activating it",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			h, err := standalone.VerifyBundle(cmd.Context(), file, key)
			if err != nil {
				return fmt.Errorf("verify bundle: %w", err)
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Verified bundle version %d (%d policies)\n", h.Version, h.Policies)
			return err
		},
	}
	cmd.Flags().StringVar(&file, "bundle-file", "", "signed bundle to verify")
	cmd.Flags().StringVar(&key, "bundle-pubkey", "", "trusted Ed25519 public key file (one or two keys)")
	_ = cmd.MarkFlagRequired("bundle-file")
	_ = cmd.MarkFlagRequired("bundle-pubkey")
	return cmd
}
