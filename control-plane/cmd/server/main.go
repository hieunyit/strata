// Command server runs the control plane: the admin API (gRPC and
// REST/JSON, OIDC + RBAC), the event API, FleetService for agents, and the
// PostgreSQL schema migrations.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"github.com/strata/strata/control-plane/rulecat"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/strata/strata/agent/pkg/bundlefmt"
	"github.com/strata/strata/control-plane/admin"
	"github.com/strata/strata/control-plane/api"
	"github.com/strata/strata/control-plane/auth"
	"github.com/strata/strata/control-plane/db"
	"github.com/strata/strata/control-plane/fleet"
	"github.com/strata/strata/control-plane/ingest"
	"github.com/strata/strata/control-plane/localauth"
	"github.com/strata/strata/control-plane/metrics"
	"github.com/strata/strata/control-plane/policy"
	"github.com/strata/strata/control-plane/replay"
	"github.com/strata/strata/control-plane/store"
)

// Set at build time: -ldflags "-X main.version=... -X main.commit=...".
var (
	version = "dev"
	commit  = ""
)

func main() {
	addr := flag.String("addr", ":8080", "REST listen address (admin and event API)")
	inMemory := flag.Bool("in-memory", false, "Keep events in memory instead of ClickHouse (development)")
	chAddr := flag.String("clickhouse-addr", "127.0.0.1:9000", "ClickHouse native protocol address")
	chUser := flag.String("clickhouse-user", "default", "ClickHouse user; the password is read from STRATA_CLICKHOUSE_PASSWORD")
	seed := flag.Bool("seed", false, "With -in-memory, add sample events")
	ttlDays := flag.Int("events-ttl-days", 90, "Retention of events in ClickHouse, in days (the table's TTL is set to it at start); 0 leaves the table as it is")
	grpcAddr := flag.String("grpc-addr", "", "FleetService (PushEvents) listen address; empty disables it")
	tlsCA := flag.String("tls-ca", "", "CA that signs node certificates (FleetService mTLS)")
	tlsCert := flag.String("tls-cert", "", "FleetService server certificate")
	tlsKey := flag.String("tls-key", "", "FleetService server key")
	adminGRPCAddr := flag.String("admin-grpc-addr", "", "Admin API gRPC listen address; empty disables it (REST still works)")
	adminTLSCert := flag.String("admin-tls-cert", "", "Admin gRPC server certificate")
	adminTLSKey := flag.String("admin-tls-key", "", "Admin gRPC server key")
	adminPlaintext := flag.Bool("admin-grpc-plaintext", false, "Serve admin gRPC without TLS (lab only: tokens travel in clear)")
	oidcIssuer := flag.String("oidc-issuer", "", "OIDC issuer whose access tokens are accepted (required unless -local-auth)")
	oidcDiscovery := flag.String("oidc-discovery-url", "", "Where to read the issuer's metadata when it is reached under another name")
	oidcAudience := flag.String("oidc-audience", "strata-api", "Audience access tokens must carry")
	oidcRoles := flag.String("oidc-roles-claim", "realm_access.roles", "Dotted path of the roles list in the token")
	nodeCACert := flag.String("node-ca-cert", "", "CA certificate that signs node certificates at enrollment (with -node-ca-key)")
	nodeCAKey := flag.String("node-ca-key", "", "Key of -node-ca-cert")
	trustBundle := flag.String("fleet-trust-bundle", "", "CA bundle enrolled agents trust for FleetService (default: -tls-ca)")
	bundlePub := flag.String("bundle-pubkey", "", "Public key that verifies bundle signatures, sent to enrolled agents")
	signingKey := flag.String("bundle-signing-key", "", "Ed25519 seed that signs bundles, with -bundle-signer=file (lab, development); deploys need a signer, -bundle-pubkey and -s3-*")
	signerKind := flag.String("bundle-signer", "file", "Who signs bundles: file (-bundle-signing-key) or vault (Vault transit; the key never leaves Vault; token from -vault-token-file or VAULT_TOKEN)")
	vaultAddr := flag.String("vault-addr", os.Getenv("VAULT_ADDR"), "Vault address, with -bundle-signer=vault")
	vaultMount := flag.String("vault-transit-mount", "transit", "Vault transit mount")
	vaultKey := flag.String("vault-transit-key", "strata-bundles", "Vault transit key (ed25519, not exportable)")
	vaultKeyVersion := flag.Int("vault-transit-key-version", 0, "Version of the Vault key that signs (0: latest); pin it while a new version is rotated in")
	vaultTokenFile := flag.String("vault-token-file", "", "File holding the Vault token (default: VAULT_TOKEN)")
	costBudget := flag.Uint64("cost-budget", policy.DefaultCostBudget, "Cost units a bundle's rules may cost; a deploy over it is refused (0: no limit)")
	rulesFlag := flag.String("rules", "", "Comma-separated rule IR files compiled into every bundle")
	blockPage := flag.String("block-page", "", "HTML of the default block page put in bundles")
	supportContact := flag.String("support-contact", "", "Support contact shown on the block page")
	compilerBin := flag.String("compiler", "strata-compile", "Bundle compiler binary")
	s3Endpoint := flag.String("s3-endpoint", "", "Object store host:port for bundles; keys from STRATA_S3_ACCESS_KEY, STRATA_S3_SECRET_KEY")
	s3Bucket := flag.String("s3-bucket", "strata-bundles", "Bucket for bundles")
	s3Secure := flag.Bool("s3-secure", true, "Use HTTPS for the object store")
	replayApproved := flag.Bool("replay-sampling-approved", false,
		"Allow sampling real traffic for replay (W12-N-01); only once the sample format (docs/spec/replay-sample.md) passed legal review")
	replayBin := flag.String("replay", "", "strata-replay binary: each new policy version is replayed against the bundle in force on the policy's traffic samples and -replay-corpus (W13-G2-01); empty: no replay. Needs deploys (signer, -bundle-pubkey, -s3-*)")
	replayCorpus := flag.String("replay-corpus", "", "Sample file of the benign and attack corpus (strata-replay gen) replayed with every draft")
	replayThreads := flag.Int("replay-threads", 2, "Threads of one replay")
	replayTimeout := flag.Duration("replay-timeout", 10*time.Minute, "Longest replay")
	rolloutWaves := flag.String("rollout-waves", "1,10%,100%", "Rollout waves: a node count for the first, then cumulative percentages")
	rolloutSoak := flag.Duration("rollout-soak", 0, "Wait after a wave is all ACTIVE before the next starts")
	metricsAddr := flag.String("metrics-addr", "", "Prometheus metrics listen address; it has no authentication, bind it where only the scraper reaches; empty disables it")
	localAuth := flag.Bool("local-auth", false, "Accept local accounts kept in PostgreSQL (username and password) besides, or instead of, OIDC")
	localTTL := flag.Duration("local-session-ttl", 8*time.Hour, "Lifetime of a local sign-in")
	localAdmin := flag.String("local-admin-user", "admin", "With -local-auth, the admin created on first start when there is no account; its password comes from STRATA_LOCAL_ADMIN_PASSWORD")
	trustedProxies := flag.String("trusted-proxies", "", "Comma-separated CIDRs, addresses or host names (resolved every 30s) of reverse proxies whose X-Forwarded-For gives the client IP of a login (throttling, audit)")
	corsOrigins := flag.String("cors-origins", "http://localhost:5173,http://127.0.0.1:5173", "Comma-separated origins allowed to call the REST API from a browser")
	flag.Parse()
	mx := metrics.New(version, commit)

	ctx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	presence := fleet.NewPresence()
	var pg *store.Store
	var pool *pgxpool.Pool

	// PostgreSQL: the DSN carries a password, so it comes from the
	// environment, not from a flag visible in ps.
	if dsn := os.Getenv("STRATA_POSTGRES_DSN"); dsn != "" {
		var err error
		pool, err = pgxpool.New(ctx, dsn)
		if err != nil {
			log.Fatalf("[FATAL] PostgreSQL: %v", err)
		}
		defer pool.Close()
		latest, err := db.Latest()
		if err != nil {
			log.Fatalf("[FATAL] migrations: %v", err)
		}
		mctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		err = retry(mctx, func() error { return db.Migrate(mctx, pool, latest) })
		cancel()
		if err != nil {
			log.Fatalf("[FATAL] migrations: %v", err)
		}
		log.Printf("[INFO] PostgreSQL schema at version %d", latest)
		pg = store.New(pool)
	} else {
		log.Println("[WARN] STRATA_POSTGRES_DSN is not set: no database (policies, nodes and audit are unavailable)")
	}

	var store ingest.EventStore
	if *inMemory {
		log.Println("[INFO] Initializing in-memory EventStore")
		memStore := ingest.NewMockEventStore()
		if *seed {
			seedDemoEvents(memStore)
		}
		store = memStore
	} else {
		log.Printf("[INFO] Connecting to ClickHouse at %s\n", *chAddr)
		chStore, err := ingest.NewClickHouseStore(ctx, ingest.ClickHouseConfig{
			Addr:     *chAddr,
			Database: "default",
			Username: *chUser,
			Password: os.Getenv("STRATA_CLICKHOUSE_PASSWORD"),
			Table:    "events",
		})
		if err != nil {
			log.Fatalf("[FATAL] Failed to connect to ClickHouse: %v", err)
		}
		defer chStore.Close()
		if err := chStore.EnsureColumns(ctx); err != nil {
			log.Fatalf("[FATAL] ClickHouse: %v", err)
		}
		if err := chStore.EnsureTTL(ctx, *ttlDays); err != nil {
			log.Fatalf("[FATAL] %v", err)
		}
		if err := chStore.EnsurePolicyRequests(ctx, *ttlDays); err != nil {
			log.Fatalf("[FATAL] ClickHouse: %v", err)
		}
		store = chStore
	}

	if *oidcIssuer == "" && !*localAuth {
		log.Fatal("[FATAL] no way to sign in: set -oidc-issuer, -local-auth, or both")
	}
	dispatch := auth.Dispatch{LocalPrefix: localauth.TokenPrefix}
	if *oidcIssuer != "" {
		vctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		v, err := auth.NewVerifier(vctx, auth.Config{
			Issuer: *oidcIssuer, DiscoveryURL: *oidcDiscovery, Audience: *oidcAudience, RolesClaim: *oidcRoles,
		})
		cancel()
		if err != nil {
			log.Fatalf("[FATAL] %v", err)
		}
		dispatch.OIDC = v
	}
	var local *localauth.Handler
	if *localAuth {
		if pool == nil {
			log.Fatal("[FATAL] -local-auth keeps accounts in PostgreSQL: set STRATA_POSTGRES_DSN")
		}
		ls := localauth.NewStore(pool)
		svc, err := localauth.NewService(ls, *localTTL)
		if err != nil {
			log.Fatalf("[FATAL] local accounts: %v", err)
		}
		if pw := os.Getenv("STRATA_LOCAL_ADMIN_PASSWORD"); pw != "" {
			created, err := svc.Bootstrap(ctx, *localAdmin, pw)
			if err != nil {
				log.Fatalf("[FATAL] local accounts: %v", err)
			}
			if created {
				log.Printf("[INFO] local accounts: created admin %q (STRATA_LOCAL_ADMIN_PASSWORD is not used again)", *localAdmin)
			}
		} else if n, err := ls.CountUsers(ctx); err == nil && n == 0 {
			log.Println("[WARN] -local-auth without any account: set STRATA_LOCAL_ADMIN_PASSWORD to create the first admin")
		}
		proxies, err := localauth.ParseTrustedProxies(*trustedProxies)
		if err != nil {
			log.Fatalf("[FATAL] -trusted-proxies: %v", err)
		}
		proxies.Run(ctx, 30*time.Second)
		local = &localauth.Handler{Service: svc, Store: ls, TrustedProxies: proxies}
		dispatch.Local = svc
		go svc.CleanExpired(ctx, 10*time.Minute)
		log.Printf("[INFO] local accounts enabled (sessions last %s)", *localTTL)
	}
	verifier := dispatch

	var adminOpts []grpc.ServerOption
	if *adminGRPCAddr != "" && !*adminPlaintext {
		if *adminTLSCert == "" || *adminTLSKey == "" {
			log.Fatal("[FATAL] -admin-grpc-addr needs -admin-tls-cert and -admin-tls-key (or -admin-grpc-plaintext in a lab)")
		}
		pair, err := tls.LoadX509KeyPair(*adminTLSCert, *adminTLSKey)
		if err != nil {
			log.Fatalf("[FATAL] admin TLS: %v", err)
		}
		adminOpts = append(adminOpts, grpc.Creds(credentials.NewTLS(&tls.Config{
			Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13,
		})))
	}
	// The bundle public key: Vault's, or the -bundle-pubkey file.
	var signer policy.Signer
	// pub verifies what this control plane signs; trust is what enrolled
	// nodes are told to trust: the -bundle-pubkey file (one key, or two
	// while the signing key is rotated), else pub.
	var pub, trust []byte
	switch *signerKind {
	case "vault":
		token := os.Getenv("VAULT_TOKEN")
		if *vaultTokenFile != "" {
			b, err := os.ReadFile(*vaultTokenFile)
			if err != nil {
				log.Fatalf("[FATAL] Vault token: %v", err)
			}
			token = strings.TrimSpace(string(b))
		}
		vs := &policy.VaultSigner{Addr: *vaultAddr, Mount: *vaultMount, Key: *vaultKey, Token: token, Version: *vaultKeyVersion}
		if err := vs.Init(ctx); err != nil {
			log.Fatalf("[FATAL] %v", err)
		}
		k, _ := vs.PublicKey(ctx)
		pub, signer = k, vs
		trust = pub
		if *bundlePub != "" {
			f, err := os.ReadFile(*bundlePub)
			if err != nil || !bundlefmt.ValidKeys(f) || (!bytes.Equal(f[:32], pub) && !bytes.Equal(f[len(f)-32:], pub)) {
				log.Fatalf("[FATAL] -bundle-pubkey %s does not hold the public key of Vault key %s (one or two 32-byte keys)", *bundlePub, *vaultKey)
			}
			trust = f
		}
		log.Printf("[INFO] Bundles are signed by Vault transit key %s at %s", *vaultKey, *vaultAddr)
	case "file":
		if *bundlePub != "" {
			var err error
			if pub, err = os.ReadFile(*bundlePub); err != nil || !bundlefmt.ValidKeys(pub) {
				log.Fatalf("[FATAL] bundle public key %s: one or two 32-byte keys (%v)", *bundlePub, err)
			}
			trust = pub
		}
	default:
		log.Fatalf("[FATAL] -bundle-signer must be file or vault")
	}
	deps := admin.Deps{Presence: presence}
	var objects *policy.S3
	var rollouts *fleet.Rollouts
	var canary *fleet.CanaryMonitor
	if pg != nil {
		deps.Fleet, deps.Policies, deps.Rollouts = pg, pg, pg
		waves, err := parseWaves(*rolloutWaves)
		if err != nil {
			log.Fatalf("[FATAL] -rollout-waves: %v", err)
		}
		rollouts = fleet.NewRollouts(pg, presence, waves, *rolloutSoak)
		deps.Kicker = rollouts
		go rollouts.Run(ctx)
		commands := fleet.NewCommands(pg, presence)
		deps.Commands, deps.CommandKicker = pg, commands
		deps.KillSwitch = pg
		deps.Replay, deps.ReplayApproved = pg, *replayApproved
		go commands.Run(ctx)
		canary = fleet.NewCanaryMonitor(pg, commands, fleet.CanaryOptions{})
		deps.CanaryTrips = pg
		go canary.Run(ctx)
		if *s3Endpoint != "" {
			objects = connectS3(ctx, policy.S3Config{Endpoint: *s3Endpoint, Bucket: *s3Bucket, Secure: *s3Secure,
				AccessKey: os.Getenv("STRATA_S3_ACCESS_KEY"), SecretKey: os.Getenv("STRATA_S3_SECRET_KEY")})
		}
		if signer != nil || *signingKey != "" {
			if k := os.Getenv("STRATA_IDENTITY_HMAC_KEY"); k != "" {
				if _, err := policy.ParseIdentityKey(k); err != nil {
					log.Fatalf("[FATAL] STRATA_IDENTITY_HMAC_KEY: %v", err)
				}
			}
			d := newDeployer(pg, pool, objects, signer, *signingKey, pub, *rulesFlag, *blockPage, *supportContact, *compilerBin, *costBudget)
			d.Publish = rollouts.Start
			deps.Deployer = mx.Deployer(d)
			if *replayBin != "" {
				runner := &replay.Runner{Store: pg, Deployable: pg.DeployablePolicies, Build: replay.ReplayBuilder(*d.Builder.(*policy.Compiler)),
					Baseline: bundleInForce(pg, objects, pub), BaselinePub: pub, Samples: objects,
					Corpus: *replayCorpus, Binary: *replayBin, Threads: *replayThreads, Timeout: *replayTimeout}
				if err := runner.Init(); err != nil {
					log.Fatalf("[FATAL] replay: %v", err)
				}
				deps.Operations, deps.ReplayKick = pg, runner.Kick
				go func() {
					if err := runner.Run(ctx); err != nil {
						log.Printf("[ERROR] replay: %v", err)
					}
				}()
				log.Printf("[INFO] Replay of drafts: %s, corpus %q", *replayBin, *replayCorpus)
			}
		} else if *replayBin != "" {
			log.Fatal("[FATAL] -replay needs deploys (-bundle-signing-key or -bundle-signer=vault, -bundle-pubkey, -s3-endpoint)")
		}
	}
	adm, err := admin.New(ctx, verifier, admin.BuildInfo{Version: version, Commit: commit}, deps, adminOpts...)
	if err != nil {
		log.Fatalf("[FATAL] %v", err)
	}
	defer adm.Close()
	if *adminGRPCAddr != "" {
		ln, err := net.Listen("tcp", *adminGRPCAddr)
		if err != nil {
			log.Fatalf("[FATAL] admin gRPC listen: %v", err)
		}
		go func() {
			log.Printf("[INFO] Admin API gRPC listening on %s", *adminGRPCAddr)
			if err := adm.GRPC.Serve(ln); err != nil {
				log.Printf("[ERROR] admin gRPC: %v", err)
			}
		}()
	}

	// what the decision trace shows about each rule: the rules compiled
	// into bundles
	catalog, err := rulecat.Load(strings.Split(*rulesFlag, ","))
	if err != nil {
		log.Printf("[WARN] rule catalog: %v (events are shown without rule names)", err)
	} else {
		log.Printf("[INFO] rule catalog: %d rules", catalog.Len())
	}

	srv := api.NewServer(api.ServerConfig{
		Addr:         *addr,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		Auth:         verifier,
		Admin:        adm.Gateway,
		Rules:        catalog,
		Local:        local,
		OIDC:         dispatch.OIDC != nil,
	}, store)

	allowedOrigins := map[string]bool{}
	for _, o := range strings.Split(*corsOrigins, ",") {
		if o = strings.TrimSpace(o); o != "" {
			allowedOrigins[o] = true
		}
	}
	handlerWithCORS := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if allowedOrigins[origin] {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		srv.Handler().ServeHTTP(w, r)
	})

	server := &http.Server{
		Addr:              *addr,
		Handler:           mx.HTTP(handlerWithCORS),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
	}
	go func() {
		log.Printf("[INFO] REST API listening on %s\n", *addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[FATAL] Server error: %v", err)
		}
	}()

	var ingestSvc *ingest.IngestService
	var gs *grpc.Server
	if *grpcAddr != "" {
		tlsCfg, err := fleet.ServerTLS(*tlsCA, *tlsCert, *tlsKey)
		if err != nil {
			log.Fatalf("[FATAL] FleetService TLS: %v", err)
		}
		ln, err := net.Listen("tcp", *grpcAddr)
		if err != nil {
			log.Fatalf("[FATAL] FleetService listen: %v", err)
		}
		ingestSvc = ingest.NewIngestService(store, ingest.DefaultBatcherConfig(), 24*time.Hour)
		fcfg := fleet.Config{Ingest: ingestSvc, Presence: presence, Rollouts: rollouts, Canary: canary}
		// requests per policy from the heartbeats (RV-N-01)
		if sink, ok := store.(fleet.PolicyRequestsSink); ok {
			fcfg.PolicyRequests = fleet.NewPolicyRequestsRecorder(sink)
			go fcfg.PolicyRequests.Run(ctx)
		}
		if objects != nil {
			fcfg.Objects = objects
			// replay samples from the nodes, as sample files (W12-N-01)
			samples := replay.NewCollector(&replay.Store{Objects: objects})
			if pg != nil {
				samples.Authorize = pg.ReplaySampleScope
			}
			fcfg.Samples = samples
			go samples.Run(ctx)
		}
		if *nodeCACert != "" {
			if pg == nil {
				log.Fatal("[FATAL] enrollment (-node-ca-cert) needs PostgreSQL (STRATA_POSTGRES_DSN)")
			}
			ca, err := fleet.LoadCA(*nodeCACert, *nodeCAKey)
			if err != nil {
				log.Fatalf("[FATAL] %v", err)
			}
			fcfg.Registry, fcfg.CA = pg, ca
			tb := *trustBundle
			if tb == "" {
				tb = *tlsCA
			}
			if fcfg.TrustBundle, err = os.ReadFile(tb); err != nil {
				log.Fatalf("[FATAL] fleet trust bundle: %v", err)
			}
			fcfg.BundlePubKey = trust
		}
		gs = fleet.NewGRPCServer(tlsCfg, fleet.NewServer(fcfg))
		go func() {
			log.Printf("[INFO] FleetService (mTLS) listening on %s\n", *grpcAddr)
			if err := gs.Serve(ln); err != nil {
				log.Fatalf("[FATAL] FleetService error: %v", err)
			}
		}()
	}

	if *metricsAddr != "" {
		src := metrics.Sources{Connected: presence.ConnectedNodes}
		if pg != nil {
			src.Enrolled, src.Active = pg.EnrolledNodes, pg.ActiveRollouts
			src.CanaryTrips, src.OpenTrips = canary.Trips, pg.OpenCanaryTrips
		}
		if ingestSvc != nil {
			src.Ingest, src.IngestErrors = ingestSvc.Stats, ingestSvc.StoreErrors
		}
		mx.Watch(src)
		ms := &http.Server{Addr: *metricsAddr, Handler: mx.Handler(), ReadHeaderTimeout: 5 * time.Second}
		go func() {
			log.Printf("[INFO] metrics listening on %s", *metricsAddr)
			if err := ms.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("[FATAL] metrics: %v", err)
			}
		}()
		defer ms.Close()
	}

	<-ctx.Done()

	log.Println("[INFO] Shutting down server gracefully...")
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(sctx); err != nil {
		log.Printf("[ERROR] Server forced to shutdown: %v\n", err)
	}
	if gs != nil {
		// Agent streams never end on their own; cut them. Unacked batches
		// are resent by the agents.
		gs.Stop()
	}
	if ingestSvc != nil {
		if err := ingestSvc.Close(sctx); err != nil {
			log.Printf("[ERROR] Flushing ingest queue: %v\n", err)
		}
	}
	log.Println("[INFO] Server stopped")
}

// connectS3 connects to the bundle bucket, waiting for it to come up.
func connectS3(ctx context.Context, cfg policy.S3Config) *policy.S3 {
	sctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	var objects *policy.S3
	if err := retry(sctx, func() error {
		var err error
		objects, err = policy.NewS3(sctx, cfg)
		return err
	}); err != nil {
		log.Fatalf("[FATAL] %v", err)
	}
	return objects
}

// newDeployer wires the compiler, the signing key and the object store.
func newDeployer(pg *store.Store, pool *pgxpool.Pool, objects *policy.S3, signer policy.Signer, key string, pub []byte, rules, blockPage, contact, bin string, budget uint64) *policy.Deployer {
	if len(pub) == 0 || objects == nil {
		log.Fatal("[FATAL] deploys need the bundle public key (-bundle-pubkey or Vault) and -s3-endpoint")
	}
	var ruleFiles []string
	for _, r := range strings.Split(rules, ",") {
		if r = strings.TrimSpace(r); r != "" {
			ruleFiles = append(ruleFiles, r)
		}
	}
	log.Printf("[INFO] Deploys: %s, %d rule files", bin, len(ruleFiles))
	return &policy.Deployer{
		Store: pg,
		Builder: &policy.Compiler{Binary: bin, Signer: signer, KeyFile: key, Rules: ruleFiles, BlockPage: blockPage,
			SupportContact: contact, CostBudget: budget,
			// P-01 §1: from a secret manager, or kept by the control plane
			IdentityKey: policy.IdentityKeys{Env: os.Getenv("STRATA_IDENTITY_HMAC_KEY"), Pool: pool}.Key},
		Objects: objects,
		PubKey:  pub,
	}
}

// bundleInForce returns the newest bundle, the one a replay compares a
// draft with (W13-G2-01), once it verifies with pub.
func bundleInForce(pg *store.Store, objects *policy.S3, pub []byte) func(context.Context) ([]byte, uint64, error) {
	return func(ctx context.Context) ([]byte, uint64, error) {
		b, err := pg.LatestBundle(ctx)
		if err != nil {
			return nil, 0, err
		}
		data, err := objects.Get(ctx, b.ObjectKey)
		if err != nil {
			return nil, 0, fmt.Errorf("bundle %d: %w", b.Version, err)
		}
		if _, err := bundlefmt.Verify(data, pub); err != nil {
			return nil, 0, fmt.Errorf("bundle %d: %w", b.Version, err)
		}
		return data, b.Version, nil
	}
}

// parseWaves reads "1,10%,100%": the first wave's node count (only 1 is
// supported, meaning one node), then cumulative percentages.
func parseWaves(s string) ([]float64, error) {
	var out []float64
	for i, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		switch {
		case i == 0 && part == "1":
			out = append(out, 0)
		case strings.HasSuffix(part, "%"):
			v, err := strconv.ParseFloat(strings.TrimSuffix(part, "%"), 64)
			if err != nil || v <= 0 || v > 100 {
				return nil, fmt.Errorf("bad percentage %q", part)
			}
			out = append(out, v/100)
		default:
			return nil, fmt.Errorf("%q: the first wave is 1 (one node), the others are percentages", part)
		}
	}
	if len(out) == 0 || out[len(out)-1] != 1 {
		return nil, fmt.Errorf("the last wave must be 100%%")
	}
	return out, nil
}

// retry calls f until it succeeds or ctx ends (the database may start after
// the control plane).
func retry(ctx context.Context, f func() error) error {
	for delay := 500 * time.Millisecond; ; delay = min(2*delay, 5*time.Second) {
		err := f()
		if err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return err
		case <-time.After(delay):
		}
	}
}

func seedDemoEvents(store *ingest.MockEventStore) {
	now := time.Now().UTC()
	events := []ingest.Event{
		{
			BlockID:       "STR-8F3K-Q2VD-7XNM-A1PC",
			Timestamp:     now.Add(-2 * time.Minute),
			NodeID:        "edge-worker-01",
			ConnectorType: "nginx",
			PolicyID:      "example-api",
			PolicyVersion: 1,
			ClientIP:      "198.51.100.42",
			Identity:      "anon-client-1",
			RequestID:     "req-001-sqli-attempt",
			HTTPMethod:    "POST",
			HTTPHost:      "api.example.test",
			HTTPPath:      "/v1/users/search",
			StatusCode:    403,
			Action:        "block",
			ScoreProtocol: 0,
			ScoreSQLi:     45,
			ScoreXSS:      0,
			ScoreAnomaly:  45,
			MatchedRules:  []uint32{942100, 942150},
			Violations: []ingest.Violation{
				{
					RuleID:  942100,
					Layer:   "sqli",
					Field:   "body.query",
					Snippet: "' OR 1=1 --",
				},
				{
					RuleID:  942150,
					Layer:   "sqli",
					Field:   "body.query",
					Snippet: "UNION SELECT null, username, password FROM users",
				},
			},
			ReceivedAt: now.Add(-2 * time.Minute),
		},
		{
			BlockID:       "STR-3B9Y-K8P2-WM4C-9D0R",
			Timestamp:     now.Add(-10 * time.Minute),
			NodeID:        "edge-worker-02",
			ConnectorType: "nginx",
			PolicyID:      "example-api",
			PolicyVersion: 1,
			ClientIP:      "203.0.113.19",
			Identity:      "guest-browser",
			RequestID:     "req-002-xss-attempt",
			HTTPMethod:    "GET",
			HTTPHost:      "api.example.test",
			HTTPPath:      "/comments",
			StatusCode:    403,
			Action:        "block",
			ScoreProtocol: 0,
			ScoreSQLi:     0,
			ScoreXSS:      30,
			ScoreAnomaly:  30,
			MatchedRules:  []uint32{941100},
			Violations: []ingest.Violation{
				{
					RuleID:  941100,
					Layer:   "xss",
					Field:   "uri.query.text",
					Snippet: "<script>alert(document.cookie)</script>",
				},
			},
			ReceivedAt: now.Add(-10 * time.Minute),
		},
		{
			BlockID:       "EVT-7X2W-5M1Q-9H8K-L0P4",
			Timestamp:     now.Add(-30 * time.Minute),
			NodeID:        "edge-worker-01",
			ConnectorType: "nginx",
			PolicyID:      "example-api",
			PolicyVersion: 1,
			ClientIP:      "192.0.2.77",
			Identity:      "scanner-bot",
			RequestID:     "req-003-shadow-probe",
			HTTPMethod:    "GET",
			HTTPHost:      "api.example.test",
			HTTPPath:      "/.env",
			StatusCode:    200,
			Action:        "shadow",
			ScoreProtocol: 15,
			ScoreSQLi:     0,
			ScoreXSS:      0,
			ScoreAnomaly:  15,
			MatchedRules:  []uint32{100005},
			Violations: []ingest.Violation{
				{
					RuleID:  100005,
					Layer:   "protocol",
					Field:   "uri.path",
					Snippet: "/.env",
				},
			},
			ReceivedAt: now.Add(-30 * time.Minute),
		},
	}

	_ = store.SaveEvents(context.Background(), events)
	log.Printf("[INFO] Pre-seeded %d demo events into memory store\n", len(events))
}
