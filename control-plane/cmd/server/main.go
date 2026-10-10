// Command server runs the control plane: the admin API (gRPC and
// REST/JSON, OIDC + RBAC), the event API, FleetService for agents, and the
// PostgreSQL schema migrations.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
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

	"github.com/strata/strata/control-plane/admin"
	"github.com/strata/strata/control-plane/api"
	"github.com/strata/strata/control-plane/auth"
	"github.com/strata/strata/control-plane/db"
	"github.com/strata/strata/control-plane/fleet"
	"github.com/strata/strata/control-plane/ingest"
	"github.com/strata/strata/control-plane/policy"
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
	grpcAddr := flag.String("grpc-addr", "", "FleetService (PushEvents) listen address; empty disables it")
	tlsCA := flag.String("tls-ca", "", "CA that signs node certificates (FleetService mTLS)")
	tlsCert := flag.String("tls-cert", "", "FleetService server certificate")
	tlsKey := flag.String("tls-key", "", "FleetService server key")
	adminGRPCAddr := flag.String("admin-grpc-addr", "", "Admin API gRPC listen address; empty disables it (REST still works)")
	adminTLSCert := flag.String("admin-tls-cert", "", "Admin gRPC server certificate")
	adminTLSKey := flag.String("admin-tls-key", "", "Admin gRPC server key")
	adminPlaintext := flag.Bool("admin-grpc-plaintext", false, "Serve admin gRPC without TLS (lab only: tokens travel in clear)")
	oidcIssuer := flag.String("oidc-issuer", "", "OIDC issuer whose access tokens are accepted (required)")
	oidcDiscovery := flag.String("oidc-discovery-url", "", "Where to read the issuer's metadata when it is reached under another name")
	oidcAudience := flag.String("oidc-audience", "strata-api", "Audience access tokens must carry")
	oidcRoles := flag.String("oidc-roles-claim", "realm_access.roles", "Dotted path of the roles list in the token")
	nodeCACert := flag.String("node-ca-cert", "", "CA certificate that signs node certificates at enrollment (with -node-ca-key)")
	nodeCAKey := flag.String("node-ca-key", "", "Key of -node-ca-cert")
	trustBundle := flag.String("fleet-trust-bundle", "", "CA bundle enrolled agents trust for FleetService (default: -tls-ca)")
	bundlePub := flag.String("bundle-pubkey", "", "Public key that verifies bundle signatures, sent to enrolled agents")
	signingKey := flag.String("bundle-signing-key", "", "Ed25519 seed that signs bundles (deploys need it, with -bundle-pubkey and -s3-*)")
	rulesFlag := flag.String("rules", "", "Comma-separated rule IR files compiled into every bundle")
	blockPage := flag.String("block-page", "", "HTML of the default block page put in bundles")
	supportContact := flag.String("support-contact", "", "Support contact shown on the block page")
	compilerBin := flag.String("compiler", "strata-compile", "Bundle compiler binary")
	s3Endpoint := flag.String("s3-endpoint", "", "Object store host:port for bundles; keys from STRATA_S3_ACCESS_KEY, STRATA_S3_SECRET_KEY")
	s3Bucket := flag.String("s3-bucket", "strata-bundles", "Bucket for bundles")
	s3Secure := flag.Bool("s3-secure", true, "Use HTTPS for the object store")
	rolloutWaves := flag.String("rollout-waves", "1,10%,100%", "Rollout waves: a node count for the first, then cumulative percentages")
	rolloutSoak := flag.Duration("rollout-soak", 0, "Wait after a wave is all ACTIVE before the next starts")
	corsOrigins := flag.String("cors-origins", "http://localhost:5173,http://127.0.0.1:5173", "Comma-separated origins allowed to call the REST API from a browser")
	flag.Parse()

	ctx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	presence := fleet.NewPresence()
	var pg *store.Store

	// PostgreSQL: the DSN carries a password, so it comes from the
	// environment, not from a flag visible in ps.
	if dsn := os.Getenv("STRATA_POSTGRES_DSN"); dsn != "" {
		pool, err := pgxpool.New(ctx, dsn)
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
		store = chStore
	}

	vctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	verifier, err := auth.NewVerifier(vctx, auth.Config{
		Issuer: *oidcIssuer, DiscoveryURL: *oidcDiscovery, Audience: *oidcAudience, RolesClaim: *oidcRoles,
	})
	cancel()
	if err != nil {
		log.Fatalf("[FATAL] %v", err)
	}

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
	deps := admin.Deps{Presence: presence}
	var objects *policy.S3
	var rollouts *fleet.Rollouts
	if pg != nil {
		deps.Fleet, deps.Policies, deps.Rollouts = pg, pg, pg
		waves, err := parseWaves(*rolloutWaves)
		if err != nil {
			log.Fatalf("[FATAL] -rollout-waves: %v", err)
		}
		rollouts = fleet.NewRollouts(pg, presence, waves, *rolloutSoak)
		deps.Kicker = rollouts
		go rollouts.Run(ctx)
		if *s3Endpoint != "" {
			objects = connectS3(ctx, policy.S3Config{Endpoint: *s3Endpoint, Bucket: *s3Bucket, Secure: *s3Secure,
				AccessKey: os.Getenv("STRATA_S3_ACCESS_KEY"), SecretKey: os.Getenv("STRATA_S3_SECRET_KEY")})
		}
		if *signingKey != "" {
			d := newDeployer(pg, objects, *signingKey, *bundlePub, *rulesFlag, *blockPage, *supportContact, *compilerBin)
			d.Publish = rollouts.Start
			deps.Deployer = d
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

	srv := api.NewServer(api.ServerConfig{
		Addr:         *addr,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		Auth:         verifier,
		Admin:        adm.Gateway,
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
		Handler:           handlerWithCORS,
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
		fcfg := fleet.Config{Ingest: ingestSvc, Presence: presence, Rollouts: rollouts}
		if objects != nil {
			fcfg.Objects = objects
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
			if *bundlePub != "" {
				if fcfg.BundlePubKey, err = os.ReadFile(*bundlePub); err != nil {
					log.Fatalf("[FATAL] bundle public key: %v", err)
				}
			}
		}
		gs = fleet.NewGRPCServer(tlsCfg, fleet.NewServer(fcfg))
		go func() {
			log.Printf("[INFO] FleetService (mTLS) listening on %s\n", *grpcAddr)
			if err := gs.Serve(ln); err != nil {
				log.Fatalf("[FATAL] FleetService error: %v", err)
			}
		}()
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
func newDeployer(pg *store.Store, objects *policy.S3, key, pubFile, rules, blockPage, contact, bin string) *policy.Deployer {
	if pubFile == "" || objects == nil {
		log.Fatal("[FATAL] -bundle-signing-key needs -bundle-pubkey and -s3-endpoint")
	}
	pub, err := os.ReadFile(pubFile)
	if err != nil {
		log.Fatalf("[FATAL] bundle public key: %v", err)
	}
	var ruleFiles []string
	for _, r := range strings.Split(rules, ",") {
		if r = strings.TrimSpace(r); r != "" {
			ruleFiles = append(ruleFiles, r)
		}
	}
	log.Printf("[INFO] Deploys: %s, %d rule files", bin, len(ruleFiles))
	return &policy.Deployer{
		Store:   pg,
		Builder: &policy.Compiler{Binary: bin, KeyFile: key, Rules: ruleFiles, BlockPage: blockPage, SupportContact: contact},
		Objects: objects,
		PubKey:  pub,
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
