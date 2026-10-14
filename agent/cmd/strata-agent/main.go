// Command strata-agent runs next to NGINX: it receives worker events on
// strata_event_socket and pushes them to the control plane (run), and
// creates the node's identity (enroll).
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	fleetv1 "github.com/strata/strata/agent/gen/strata/fleet/v1"
	"github.com/strata/strata/agent/internal/agent"
	"github.com/strata/strata/agent/internal/enroll"
)

// Set at build time: -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "strata-agent:", err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "strata-agent",
		Short:         "Strata node agent: events and bundles between NGINX and the control plane",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newRunCmd(), newEnrollCmd(), &cobra.Command{
		Use:   "version",
		Short: "Print the agent version",
		Run:   func(cmd *cobra.Command, _ []string) { fmt.Fprintln(cmd.OutOrStdout(), version) },
	})
	return root
}

func newRunCmd() *cobra.Command {
	var cfg agent.Config
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Receive worker events and push them to the control plane",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg.EventSocket = strings.TrimPrefix(cfg.EventSocket, "unix:")
			cfg.AgentVersion = version
			return run(cmd.Context(), cfg)
		},
	}
	f := cmd.Flags()
	f.StringVar(&cfg.EventSocket, "event-socket", "unix:/run/strata/events.sock", "event socket (strata_event_socket)")
	f.StringVar(&cfg.SpoolDir, "spool-dir", "/var/lib/strata/spool", "directory for unacked event batches")
	f.Int64Var(&cfg.SpoolMaxBytes, "spool-max-bytes", 2<<30, "spool size cap; the oldest batches are dropped beyond it")
	f.StringVar(&cfg.Server, "server", "", "control plane host:port")
	f.StringVar(&cfg.ServerName, "server-name", "", "TLS name of the control plane (default: host of --server)")
	f.StringVar(&cfg.CAFile, "tls-ca", "", "CA bundle trusted for the control plane")
	f.StringVar(&cfg.CertFile, "tls-cert", "", "client certificate")
	f.StringVar(&cfg.KeyFile, "tls-key", "", "client certificate key")
	f.StringVar(&cfg.NodeID, "node-id", "", "node id stamped on every event")
	f.StringVar(&cfg.IdentityDir, "identity-dir", "", "enrolled identity (strata-agent enroll); replaces --tls-ca, --tls-cert, --tls-key and --node-id")
	f.StringVar(&cfg.BundleDir, "bundle-dir", "", "install rolled-out bundles here (strata_bundle_dir); empty: do not install bundles")
	f.StringVar(&cfg.ControlFile, "control-file", "/run/strata/control", "control file the NGINX workers read (strata_control_file)")
	f.StringVar(&cfg.BundlePubKey, "bundle-pubkey", "", "Ed25519 key that signs bundles (default: bundle.pub of --identity-dir)")
	f.StringVar(&cfg.MetricsFile, "metrics-file", "/dev/shm/strata/metrics", "counters written by the NGINX workers")
	f.StringVar(&cfg.MetricsAddr, "metrics-addr", "127.0.0.1:9469", "address of the Prometheus endpoint /metrics")
	f.BoolVar(&cfg.Fallback, "fallback", true, "force every policy into shadow when the node blocks 3x its shadow level, counting at most 3 blocks per client address every 5 s (needs --bundle-dir and --metrics-file)")
	f.BoolVar(&cfg.FallbackOptions.Errors, "fallback-on-errors", false, "also force shadow when engine errors or budget overruns jump (shadow does not change the fail mode; by default these jumps are only reported)")
	f.Float64Var(&cfg.FallbackOptions.Factor, "fallback-factor", 3, "how many times the learnt level trips the node fallback")
	return cmd
}

func run(ctx context.Context, cfg agent.Config) error {
	if cfg.Server == "" || (cfg.NodeID == "" && cfg.IdentityDir == "") {
		return errors.New("--server and either --identity-dir or --node-id are required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	a, err := agent.New(cfg)
	if err != nil {
		return err
	}
	slog.Info("strata-agent started", "socket", cfg.EventSocket, "server", cfg.Server, "spool", cfg.SpoolDir)
	runErr := a.Run(ctx)
	if err := a.Close(); err != nil && runErr == nil {
		runErr = err
	}
	return runErr
}

func newEnrollCmd() *cobra.Command {
	var (
		dir, server, serverName, caFile, token, tokenFile string
		dryRun, force                                     bool
	)
	cmd := &cobra.Command{
		Use:   "enroll",
		Short: "Create this node's key and CSR, and exchange an enrollment token for a certificate",
		Long: `enroll generates a P-256 private key (written 0600, it never leaves the node)
and a CSR. With --dry-run it stops there and prints the CSR. Otherwise it sends
the CSR with the one-time token to the control plane's FleetService and stores
the certificate, the CA bundle and the bundle signing key next to the key.

The token can come from --token, --token-file or STRATA_ENROLL_TOKEN; prefer
the file or the variable, since arguments are visible in the process list.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			host, err := os.Hostname()
			if err != nil {
				return err
			}
			id, err := enroll.NewIdentity(host)
			if err != nil {
				return err
			}
			if dryRun {
				if err := id.Save(dir, force); err != nil {
					return err
				}
				out := cmd.OutOrStdout()
				fmt.Fprintf(out, "key: %s/%s (0600)\ncsr: %s/%s\n", dir, enroll.KeyFile, dir, enroll.CSRFile)
				_, err := out.Write(id.CSRPEM())
				return err
			}
			tok, err := readToken(token, tokenFile)
			if err != nil {
				return err
			}
			// Write the key first: a crash after the control plane signed
			// must not lose the key the certificate belongs to.
			if err := id.Save(dir, force); err != nil {
				return err
			}
			resp, err := enroll.Enroll(cmd.Context(), dir, id, enroll.Options{
				Server: server, ServerName: serverName, CAFile: caFile, Token: tok, Timeout: 30 * time.Second,
				Node: &fleetv1.NodeInfo{Hostname: host, AgentVersion: version, Connector: &fleetv1.Connector{Type: "nginx"}},
			})
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "enrolled as node %s; identity in %s\n", resp.GetNodeId(), dir)
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&dir, "identity-dir", "/var/lib/strata/identity", "where the key, CSR and certificate are kept")
	f.StringVar(&server, "server", "", "control plane FleetService host:port")
	f.StringVar(&serverName, "server-name", "", "TLS name of the control plane (default: host of --server)")
	f.StringVar(&caFile, "tls-ca", "", "CA trusted for the control plane during enrollment")
	f.StringVar(&token, "token", "", "one-time enrollment token")
	f.StringVar(&tokenFile, "token-file", "", "file holding the enrollment token")
	f.BoolVar(&dryRun, "dry-run", false, "only create the key and CSR, do not contact the control plane")
	f.BoolVar(&force, "force", false, "replace an existing key")
	return cmd
}

func readToken(flagValue, file string) (string, error) {
	switch {
	case flagValue != "":
		return flagValue, nil
	case file != "":
		b, err := os.ReadFile(file)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(b)), nil
	case os.Getenv("STRATA_ENROLL_TOKEN") != "":
		return os.Getenv("STRATA_ENROLL_TOKEN"), nil
	}
	return "", errors.New("an enrollment token is required (--token, --token-file or STRATA_ENROLL_TOKEN)")
}
