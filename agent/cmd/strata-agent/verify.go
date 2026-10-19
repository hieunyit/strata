package main

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/strata/strata/agent/internal/standalone"
	"github.com/strata/strata/agent/pkg/bundlefmt"
)

func newVerifyBundleCmd() *cobra.Command {
	var file, key, policy string
	var enforce bool
	cmd := &cobra.Command{
		Use: "verify-bundle", Short: "Verify a bundle signature without activating it",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if (cmd.Flags().Changed("policy") && policy == "") || (enforce && policy == "") {
				return fmt.Errorf("--policy must name a policy when supplied or used with --require-enforce")
			}
			var h bundlefmt.Header
			var err error
			if policy != "" {
				h, err = standalone.VerifyBundlePolicy(cmd.Context(), file, key, policy, enforce)
			} else {
				h, err = standalone.VerifyBundle(cmd.Context(), file, key)
			}
			if err != nil {
				return fmt.Errorf("verify bundle: %w", err)
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Verified bundle version %d (%d policies)\n", h.Version, h.Policies)
			return err
		},
	}
	cmd.Flags().StringVar(&policy, "policy", "", "require this policy in the signed bundle")
	cmd.Flags().BoolVar(&enforce, "require-enforce", false, "require the selected policy to enforce all clients (no canary)")
	cmd.Flags().StringVar(&file, "bundle-file", "", "signed bundle to verify")
	cmd.Flags().StringVar(&key, "bundle-pubkey", "", "trusted Ed25519 public key file (one or two keys)")
	_ = cmd.MarkFlagRequired("bundle-file")
	_ = cmd.MarkFlagRequired("bundle-pubkey")
	return cmd
}
