// Package fleet serves strata.fleet.v1.FleetService for strata-agent
// (nginx-module.md › "Giao thức gRPC agent ↔ control plane").
//
// The node is identified by its mTLS client certificate
// (spiffe://strata/node/<node_id>), never by the node_id an event
// carries. Every RPC but Enroll needs that certificate; with a Registry
// the node must also exist, not be revoked, and present its current
// certificate. Enroll is authenticated by its one-time token instead.
package fleet

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base32"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	eventv1 "github.com/strata/strata/agent/gen/strata/event/v1"
	fleetv1 "github.com/strata/strata/agent/gen/strata/fleet/v1"
	"github.com/strata/strata/control-plane/ingest"
	"github.com/strata/strata/control-plane/store"
)

const (
	spiffePrefix = "spiffe://strata/node/"
	// MaxBatchEvents bounds one EventBatch; the agent sends at most 500.
	MaxBatchEvents = 5000
	maxNodeID      = 128
)

// helloTimeout: a Connect stream must start with Hello (a variable for
// tests).
var helloTimeout = 10 * time.Second

// Ingester is the part of ingest.IngestService the server uses.
type Ingester interface {
	ProcessBatch(ctx context.Context, batch ingest.EventBatch) (*ingest.EventAck, error)
}

// Registry is the node database (store.Store).
type Registry interface {
	Enroll(ctx context.Context, token string, n store.Node, now time.Time, issue func(groupID string) (store.Issued, error)) (store.Node, store.Issued, error)
	GetNode(ctx context.Context, id string) (store.Node, error)
	NodeSeen(ctx context.Context, id string, at time.Time, hostname, proxyVersion, moduleVersion string, bundleVersion *int64) error
	NodeDisconnected(ctx context.Context, id string, at time.Time) error
	RenewCertificate(ctx context.Context, id, oldSerial string, iss store.Issued) error
	// DesiredBundle is the bundle a node should run (store.ErrNotFound: none).
	DesiredBundle(ctx context.Context, node string) (store.Bundle, error)
	ReportBundleStatus(ctx context.Context, node string, version uint64, state, msg string) error
	CompleteCommand(ctx context.Context, node, id string, ok bool, msg, output string, now time.Time) error
}

// BundleObjects opens a stored bundle at an offset (policy.S3).
type BundleObjects interface {
	Open(ctx context.Context, key string, offset int64) (io.ReadCloser, error)
}

// Config of the server. Ingest is required; without Registry and CA only
// PushEvents works, for nodes whose certificates the lab CA issued.
type Config struct {
	Ingest   Ingester
	Registry Registry
	CA       *CA
	// TrustBundle is sent to enrolled agents: the CA(s) that sign the
	// control plane's server certificate.
	TrustBundle []byte
	// BundlePubKey verifies bundle signatures on the node.
	BundlePubKey []byte
	Presence     *Presence
	// Objects serves FetchBundle; Rollouts is told of bundle statuses.
	Objects  BundleObjects
	Rollouts *Rollouts
	// Canary, when set, gets every heartbeat's canary counters (W12-G2-01).
	Canary *CanaryMonitor
	// PolicyRequests, when set, gets every heartbeat's per-policy request
	// counts (RV-N-01).
	PolicyRequests *PolicyRequestsRecorder
	// Samples, when set, gets the replay samples of the event batches that
	// were not received before (W12-N-01); without it they are dropped.
	Samples SampleSink
	Now     func() time.Time
}

// Server implements FleetService.
type Server struct {
	fleetv1.UnimplementedFleetServiceServer
	cfg Config
}

// NewServer returns a FleetService.
func NewServer(cfg Config) *Server {
	if cfg.Presence == nil {
		cfg.Presence = NewPresence()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Server{cfg: cfg}
}

// Presence is the stream registry, shared with the admin API.
func (s *Server) Presence() *Presence { return s.cfg.Presence }

// NewGRPCServer returns a gRPC server with mTLS and FleetService
// registered. Keepalive pings find dead connections within 15 s, so a
// node that disappears turns offline quickly.
func NewGRPCServer(tlsCfg *tls.Config, srv *Server) *grpc.Server {
	gs := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(tlsCfg)),
		grpc.KeepaliveParams(keepalive.ServerParameters{Time: 10 * time.Second, Timeout: 5 * time.Second}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: 5 * time.Second, PermitWithoutStream: true}),
		grpc.ChainUnaryInterceptor(srv.unaryAuth),
		grpc.ChainStreamInterceptor(srv.streamAuth),
	)
	fleetv1.RegisterFleetServiceServer(gs, srv)
	return gs
}

// ServerTLS loads the server certificate and the CA that signs node
// certificates. TLS 1.3; a client certificate is verified when given and
// required by every RPC except Enroll (see the interceptors).
func ServerTLS(caFile, certFile, keyFile string) (*tls.Config, error) {
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("fleet: server certificate: %w", err)
	}
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("fleet: read CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("fleet: no certificate in %s", caFile)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{pair},
		ClientCAs:    pool,
		ClientAuth:   tls.VerifyClientCertIfGiven,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

func peerCert(ctx context.Context) (*x509.Certificate, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil, errors.New("no peer")
	}
	info, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(info.State.VerifiedChains) == 0 || len(info.State.VerifiedChains[0]) == 0 {
		return nil, errors.New("no verified client certificate")
	}
	return info.State.VerifiedChains[0][0], nil
}

// NodeID returns the node id of the verified client certificate.
func NodeID(ctx context.Context) (string, error) {
	if id, ok := ctx.Value(nodeKey{}).(string); ok {
		return id, nil
	}
	cert, err := peerCert(ctx)
	if err != nil {
		return "", err
	}
	return idOf(cert)
}

func idOf(cert *x509.Certificate) (string, error) {
	for _, u := range cert.URIs {
		s := u.String()
		if id, ok := strings.CutPrefix(s, spiffePrefix); ok && validNodeID(id) {
			return id, nil
		}
	}
	return "", errors.New("client certificate has no spiffe://strata/node/ id")
}

func validNodeID(id string) bool {
	if id == "" || len(id) > maxNodeID {
		return false
	}
	for _, r := range id {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' && r != '_' && r != '.' {
			return false
		}
	}
	return true
}

type nodeKey struct{}

// authorize identifies the node of every RPC but Enroll and checks it
// against the registry.
func (s *Server) authorize(ctx context.Context, method string) (context.Context, error) {
	if method == fleetv1.FleetService_Enroll_FullMethodName {
		return ctx, nil
	}
	cert, err := peerCert(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}
	id, err := idOf(cert)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}
	if s.cfg.Registry != nil {
		n, err := s.cfg.Registry.GetNode(ctx, id)
		switch {
		case errors.Is(err, store.ErrNotFound):
			return nil, status.Error(codes.PermissionDenied, "unknown node")
		case err != nil:
			log.Printf("[ERROR] fleet: node %s: %v", id, err)
			return nil, status.Error(codes.Unavailable, "node registry unavailable")
		case n.RevokedAt != nil:
			return nil, status.Error(codes.PermissionDenied, "node revoked")
		case n.CertSerial != cert.SerialNumber.Text(16):
			return nil, status.Error(codes.PermissionDenied, "certificate superseded; use the renewed one")
		}
	}
	return context.WithValue(ctx, nodeKey{}, id), nil
}

func (s *Server) unaryAuth(ctx context.Context, req any, info *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
	ctx, err := s.authorize(ctx, info.FullMethod)
	if err != nil {
		return nil, err
	}
	return h(ctx, req)
}

type authedStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (a *authedStream) Context() context.Context { return a.ctx }

func (s *Server) streamAuth(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, h grpc.StreamHandler) error {
	ctx, err := s.authorize(ss.Context(), info.FullMethod)
	if err != nil {
		return err
	}
	return h(srv, &authedStream{ServerStream: ss, ctx: ctx})
}

var nodeIDEncoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

func newNodeID() (string, error) {
	b := make([]byte, 10)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "node-" + nodeIDEncoding.EncodeToString(b), nil
}

// clean keeps printable text of at most n bytes from agent-reported fields.
func clean(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}
		return -1
	}, s)
	if len(s) > n {
		s = s[:n]
	}
	return s
}

// Enroll exchanges a one-time token and a CSR for a node certificate.
func (s *Server) Enroll(ctx context.Context, req *fleetv1.EnrollRequest) (*fleetv1.EnrollResponse, error) {
	if s.cfg.Registry == nil || s.cfg.CA == nil {
		return nil, status.Error(codes.Unimplemented, "enrollment is not configured on this control plane")
	}
	tok := req.GetToken()
	if tok == "" || len(tok) > 256 {
		return nil, status.Error(codes.InvalidArgument, "enrollment token missing")
	}
	if _, err := checkCSR(req.GetCsr()); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	id, err := newNodeID()
	if err != nil {
		return nil, status.Error(codes.Internal, "node id")
	}
	ni := req.GetNode()
	n := store.Node{
		ID: id, Hostname: clean(ni.GetHostname(), 253),
		ProxyVersion: clean(ni.GetConnector().GetProxyVersion(), 64), ModuleVersion: clean(ni.GetConnector().GetModuleVersion(), 64),
	}
	var certPEM []byte
	n, iss, err := s.cfg.Registry.Enroll(ctx, tok, n, s.cfg.Now(), func(string) (store.Issued, error) {
		var (
			serial   string
			notAfter time.Time
			err      error
		)
		certPEM, serial, notAfter, err = s.cfg.CA.Sign(req.GetCsr(), id)
		return store.Issued{Serial: serial, NotAfter: notAfter, CertPEM: certPEM}, err
	})
	switch {
	case errors.Is(err, store.ErrTokenInvalid):
		return nil, status.Error(codes.PermissionDenied, "enrollment token is not valid")
	case err != nil:
		log.Printf("[ERROR] fleet: enroll: %v", err)
		return nil, status.Error(codes.Internal, "enrollment failed")
	}
	log.Printf("[INFO] fleet: node %s enrolled in group %s (certificate %s, until %s)", n.ID, n.GroupID, iss.Serial, iss.NotAfter.Format(time.RFC3339))
	return &fleetv1.EnrollResponse{
		NodeId: n.ID, Certificate: certPEM, CaBundle: s.cfg.TrustBundle, BundlePubkey: s.cfg.BundlePubKey,
	}, nil
}

// RenewCertificate issues a new certificate for a new key of the node.
func (s *Server) RenewCertificate(ctx context.Context, req *fleetv1.RenewRequest) (*fleetv1.RenewResponse, error) {
	if s.cfg.Registry == nil || s.cfg.CA == nil {
		return nil, status.Error(codes.Unimplemented, "renewal is not configured on this control plane")
	}
	id, _ := NodeID(ctx)
	cert, _ := peerCert(ctx)
	certPEM, serial, notAfter, err := s.cfg.CA.Sign(req.GetCsr(), id)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if err := s.cfg.Registry.RenewCertificate(ctx, id, cert.SerialNumber.Text(16), store.Issued{Serial: serial, NotAfter: notAfter}); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, status.Error(codes.PermissionDenied, "certificate superseded")
		}
		log.Printf("[ERROR] fleet: renew %s: %v", id, err)
		return nil, status.Error(codes.Internal, "renewal failed")
	}
	return &fleetv1.RenewResponse{Certificate: certPEM, CaBundle: s.cfg.TrustBundle}, nil
}

// Connect is the long-lived control stream: the agent sends Hello, then
// heartbeats; the node is online while the stream is open.
func (s *Server) Connect(st fleetv1.FleetService_ConnectServer) error {
	id, _ := NodeID(st.Context())
	ctx, out, done := s.cfg.Presence.AttachControl(st.Context(), id)
	defer done()
	defer func() {
		if s.cfg.Registry == nil || s.otherStreams(id) {
			return
		}
		// Not the request's context: it is already done.
		dctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.cfg.Registry.NodeDisconnected(dctx, id, s.cfg.Now()); err != nil {
			log.Printf("[WARN] fleet: node %s disconnected: %v", id, err)
		}
	}()

	msgs := make(chan *fleetv1.AgentMessage)
	errc := make(chan error, 1)
	go func() {
		for {
			m, err := st.Recv()
			if err != nil {
				errc <- err
				return
			}
			select {
			case msgs <- m:
			case <-ctx.Done():
				return
			}
		}
	}()

	hello := time.NewTimer(helloTimeout)
	defer hello.Stop()
	greeted := false
	group := "" // the node's connector group, read at Hello
	for {
		select {
		case <-ctx.Done():
			if st.Context().Err() == nil {
				return status.Error(codes.PermissionDenied, "node revoked")
			}
			return nil
		case <-hello.C:
			if !greeted {
				return status.Error(codes.InvalidArgument, "the stream must start with Hello")
			}
		case m := <-out:
			if err := st.Send(m); err != nil {
				return err
			}
		case err := <-errc:
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		case m := <-msgs:
			switch msg := m.GetMsg().(type) {
			case *fleetv1.AgentMessage_Hello:
				greeted = true
				group = s.nodeGroup(ctx, id)
				ni := msg.Hello.GetNode()
				if err := s.inventory(ctx, id, ni); err != nil {
					return err
				}
				v := int64(msg.Hello.GetActiveBundleVersion())
				s.seen(ctx, id, clean(ni.GetHostname(), 253), clean(ni.GetConnector().GetProxyVersion(), 64),
					clean(ni.GetConnector().GetModuleVersion(), 64), &v)
				// After a reconnect the node gets its desired version again.
				if m := s.desired(ctx, id, msg.Hello.GetActiveBundleVersion()); m != nil {
					if err := st.Send(m); err != nil {
						return err
					}
				}
				// and the rules its group has switched off (W12-G2-02)
				if m := s.disabledRules(ctx, id); m != nil {
					if err := st.Send(m); err != nil {
						return err
					}
				}
				// and its group's replay sampling (W12-N-01)
				if m := s.replaySampling(ctx, id); m != nil {
					if err := st.Send(m); err != nil {
						return err
					}
				}
			case *fleetv1.AgentMessage_Heartbeat:
				if !greeted {
					return status.Error(codes.InvalidArgument, "the stream must start with Hello")
				}
				if ni := msg.Heartbeat.GetNode(); ni != nil {
					if err := s.inventory(ctx, id, ni); err != nil {
						return err
					}
				}
				if writer, ok := s.cfg.Registry.(interface {
					RecordNodeTelemetry(context.Context, string, store.NodeTelemetry, time.Time) error
				}); ok {
					counters := msg.Heartbeat.GetCounters()
					telemetry := store.NodeTelemetry{MetricsAvailable: counters.GetMetricsAvailable(), Requests: counters.GetRequests(), Blocked: counters.GetBlocked(), FailOpen: counters.GetFailOpen(), DroppedEvents: counters.GetDroppedEvents(), AgentStartedMs: counters.GetAgentStartedMs(), MetricsCreatedMs: counters.GetMetricsCreatedMs()}
					if h := msg.Heartbeat.GetHealth(); h != nil {
						telemetry.Spool = &store.SpoolTelemetry{Bytes: h.GetSpoolBytes(), LimitBytes: h.GetSpoolLimitBytes(), PendingBatches: h.GetPendingBatches(), DroppedEvents: h.GetDroppedEvents()}
					}
					if err := writer.RecordNodeTelemetry(ctx, id, telemetry, s.cfg.Now()); err != nil {
						return status.Error(codes.Unavailable, "could not record node health")
					}
				}
				v := int64(msg.Heartbeat.GetActiveBundleVersion())
				s.seen(ctx, id, "", "", "", &v)
				if s.cfg.Canary != nil {
					s.cfg.Canary.Observe(id, group, msg.Heartbeat.GetCounters(), s.cfg.Now())
				}
				if s.cfg.PolicyRequests != nil {
					s.cfg.PolicyRequests.Observe(id, msg.Heartbeat.GetCounters(), s.cfg.Now())
				}
			case *fleetv1.AgentMessage_BundleStatus:
				if !greeted {
					return status.Error(codes.InvalidArgument, "the stream must start with Hello")
				}
				s.bundleStatus(ctx, id, msg.BundleStatus)
			case *fleetv1.AgentMessage_CommandResult:
				if !greeted {
					return status.Error(codes.InvalidArgument, "the stream must start with Hello")
				}
				s.commandResult(ctx, id, msg.CommandResult)
			default:
				if !greeted {
					return status.Error(codes.InvalidArgument, "the stream must start with Hello")
				}
			}
		}
	}
}

// Limits on what an agent reports for a command: the result is untrusted
// data, stored and shown as text.
const (
	maxCommandError  = 1024
	maxCommandOutput = 16 << 10
)

// commandResult closes one of the node's open commands; an id of another
// node or of a closed command changes nothing.
func (s *Server) commandResult(ctx context.Context, node string, r *fleetv1.CommandResult) {
	if s.cfg.Registry == nil || len(r.GetCommandId()) == 0 || len(r.GetCommandId()) > 64 {
		return
	}
	if strings.HasPrefix(r.GetCommandId(), syncCommandPrefix) {
		if !r.GetOk() {
			log.Printf("[WARN] fleet: node %s refused the disabled rules: %s", node, clean(r.GetError(), maxCommandError))
		}
		return // not a stored command
	}
	out := r.GetOutput()
	if len(out) > maxCommandOutput || !utf8.ValidString(out) {
		out = ""
	}
	err := s.cfg.Registry.CompleteCommand(ctx, node, r.GetCommandId(), r.GetOk(), clean(r.GetError(), maxCommandError), out, s.cfg.Now())
	switch {
	case errors.Is(err, store.ErrNotFound):
		log.Printf("[WARN] fleet: node %s answered unknown or closed command %q", node, clean(r.GetCommandId(), 64))
	case err != nil:
		log.Printf("[ERROR] fleet: node %s command %s: %v", node, clean(r.GetCommandId(), 64), err)
	}
}

var bundleStates = map[fleetv1.BundleStatus_State]string{
	fleetv1.BundleStatus_STATE_DOWNLOADING: "DOWNLOADING",
	fleetv1.BundleStatus_STATE_VERIFIED:    "VERIFIED",
	fleetv1.BundleStatus_STATE_ACTIVE:      "ACTIVE",
	fleetv1.BundleStatus_STATE_FAILED:      "FAILED",
}

func (s *Server) bundleStatus(ctx context.Context, node string, bs *fleetv1.BundleStatus) {
	state, ok := bundleStates[bs.GetState()]
	if !ok || s.cfg.Registry == nil {
		return
	}
	msg := clean(bs.GetError(), 1024)
	if err := s.cfg.Registry.ReportBundleStatus(ctx, node, bs.GetVersion(), state, msg); err != nil {
		log.Printf("[WARN] fleet: node %s bundle %d %s: %v", node, bs.GetVersion(), state, err)
		return
	}
	log.Printf("[INFO] fleet: node %s bundle %d %s %s", node, bs.GetVersion(), state, msg)
	if s.cfg.Rollouts != nil {
		s.cfg.Rollouts.Kick()
	}
}

// replaySampling is the SetReplaySampling of a connecting node, or nil
// without a store that keeps it.
func (s *Server) replaySampling(ctx context.Context, node string) *fleetv1.ControlMessage {
	src, ok := s.cfg.Registry.(ReplaySource)
	if !ok {
		return nil
	}
	r, err := src.NodeReplaySampling(ctx, node)
	if err != nil {
		log.Printf("[WARN] fleet: replay sampling of %s: %v", node, err)
		return nil
	}
	return ReplayMessage(syncCommandPrefix+"replay-"+node, r)
}

// SampleSink takes replay samples (replay.Collector).
type SampleSink interface {
	Add(ctx context.Context, node string, samples []*eventv1.ReplaySample)
}

// nodeGroup: the connector group of a node, "" when unknown.
func (s *Server) nodeGroup(ctx context.Context, id string) string {
	if s.cfg.Registry == nil || s.cfg.Canary == nil {
		return ""
	}
	n, err := s.cfg.Registry.GetNode(ctx, id)
	if err != nil {
		log.Printf("[WARN] fleet: node %s: %v", id, err)
		return ""
	}
	return n.GroupID
}

// DisabledRulesSource is implemented by registries that keep the kill
// switch (store.Store).
type DisabledRulesSource interface {
	NodeDisabledRules(ctx context.Context, node string) ([]int32, error)
}

// syncCommandPrefix: ids of the commands sent on Hello, which are not
// stored in node_commands.
const syncCommandPrefix = "sync-"

// disabledRules is the DisableRules (replace) bringing a connecting node's
// list in line with its group, or nil without a kill switch store.
func (s *Server) disabledRules(ctx context.Context, node string) *fleetv1.ControlMessage {
	src, ok := s.cfg.Registry.(DisabledRulesSource)
	if !ok {
		return nil
	}
	ids, err := src.NodeDisabledRules(ctx, node)
	if err != nil {
		log.Printf("[WARN] fleet: disabled rules of %s: %v", node, err)
		return nil
	}
	return CommandMessage(store.Command{ID: syncCommandPrefix + node, Kind: store.CommandSetRules, RuleIDs: ids})
}

// desired is the BundleAvailable for a node not running its desired
// version, or nil.
func (s *Server) desired(ctx context.Context, node string, active uint64) *fleetv1.ControlMessage {
	if s.cfg.Registry == nil {
		return nil
	}
	b, err := s.cfg.Registry.DesiredBundle(ctx, node)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			log.Printf("[WARN] fleet: desired bundle of %s: %v", node, err)
		}
		return nil
	}
	if b.Version == active {
		return nil
	}
	return BundleAvailable(b, b.Version < active)
}

// BundleAvailable is the control message announcing b.
func BundleAvailable(b store.Bundle, rollback bool) *fleetv1.ControlMessage {
	return &fleetv1.ControlMessage{Msg: &fleetv1.ControlMessage_BundleAvailable{BundleAvailable: &fleetv1.BundleAvailable{
		Version: b.Version, Sha256: b.SHA256, SizeBytes: uint64(b.SizeBytes), Rollback: rollback,
	}}}
}

// ChunkSize of FetchBundle.
const ChunkSize = 1 << 20

// FetchBundle streams the node's desired bundle from offset, in chunks of
// 1 MB; an interrupted download resumes with the offset it reached. A
// node gets only the version it should run.
func (s *Server) FetchBundle(req *fleetv1.FetchBundleRequest, st fleetv1.FleetService_FetchBundleServer) error {
	if s.cfg.Registry == nil || s.cfg.Objects == nil {
		return status.Error(codes.Unimplemented, "bundle distribution is not configured on this control plane")
	}
	node, _ := NodeID(st.Context())
	b, err := s.cfg.Registry.DesiredBundle(st.Context(), node)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return status.Error(codes.NotFound, "no bundle is due for this node")
	case err != nil:
		log.Printf("[ERROR] fleet: desired bundle of %s: %v", node, err)
		return status.Error(codes.Unavailable, "node registry unavailable")
	case req.GetVersion() != b.Version:
		return status.Errorf(codes.PermissionDenied, "bundle %d is not the one this node should run (%d)", req.GetVersion(), b.Version)
	case req.GetOffset() > uint64(b.SizeBytes):
		return status.Errorf(codes.OutOfRange, "offset %d past the end (%d bytes)", req.GetOffset(), b.SizeBytes)
	}
	r, err := s.cfg.Objects.Open(st.Context(), b.ObjectKey, int64(req.GetOffset()))
	if err != nil {
		log.Printf("[ERROR] fleet: open %s: %v", b.ObjectKey, err)
		return status.Error(codes.Unavailable, "bundle storage unavailable")
	}
	defer r.Close()
	buf := make([]byte, ChunkSize)
	off := req.GetOffset()
	for off < uint64(b.SizeBytes) {
		n, err := io.ReadFull(r, buf[:min(uint64(len(buf)), uint64(b.SizeBytes)-off)])
		if n > 0 {
			if err := st.Send(&fleetv1.BundleChunk{Offset: off, Data: buf[:n]}); err != nil {
				return err
			}
			off += uint64(n)
		}
		if err != nil && off < uint64(b.SizeBytes) {
			log.Printf("[ERROR] fleet: read %s at %d: %v", b.ObjectKey, off, err)
			return status.Error(codes.Unavailable, "bundle storage read failed")
		}
	}
	return nil
}

// otherStreams reports whether node still has a Connect stream here besides
// the one ending (a reconnect overlapping the old stream).
func (s *Server) otherStreams(node string) bool {
	return s.cfg.Presence.connects(node) > 1
}

func (s *Server) seen(ctx context.Context, id, host, proxy, module string, bundle *int64) {
	if s.cfg.Registry == nil {
		return
	}
	if err := s.cfg.Registry.NodeSeen(ctx, id, s.cfg.Now(), host, proxy, module, bundle); err != nil && ctx.Err() == nil {
		log.Printf("[WARN] fleet: node %s seen: %v", id, err)
	}
}

// PushEvents commits each batch through the ingest service and acks it.
func (s *Server) PushEvents(st fleetv1.FleetService_PushEventsServer) error {
	node, err := NodeID(st.Context())
	if err != nil {
		return status.Error(codes.Unauthenticated, err.Error())
	}
	ctx, done := s.cfg.Presence.Attach(st.Context(), node, KindEvents)
	defer done()
	type recvd struct {
		b   *fleetv1.EventBatch
		err error
	}
	in := make(chan recvd)
	go func() {
		for {
			b, err := st.Recv()
			select {
			case in <- recvd{b, err}:
			case <-ctx.Done():
				return
			}
			if err != nil {
				return
			}
		}
	}()
	for {
		var r recvd
		select {
		case <-ctx.Done():
			if st.Context().Err() == nil {
				return status.Error(codes.PermissionDenied, "node revoked")
			}
			return nil
		case r = <-in:
		}
		b, err := r.b, r.err
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if n := len(b.GetEvents()) + len(b.GetSamples()); n > MaxBatchEvents {
			return status.Errorf(codes.InvalidArgument, "batch of %d events and samples, at most %d", n, MaxBatchEvents)
		}
		now := time.Now().UTC()
		events := make([]ingest.Event, 0, len(b.GetEvents()))
		for _, ev := range b.GetEvents() {
			events = append(events, toIngest(ev, node, now))
		}
		ack, err := s.cfg.Ingest.ProcessBatch(ctx, ingest.EventBatch{NodeID: node, Seq: b.GetSeq(), Events: events})
		if err != nil {
			// The ingest queue is full or the store is failing: the agent
			// slows down and resends from its last ack.
			return status.Errorf(codes.ResourceExhausted, "ingest: %v", err)
		}
		// blocks by source for the cluster canary tier (#74): once, with the
		// batch that is new
		if ack.Success && !ack.Duplicate && s.cfg.Canary != nil {
			for _, ev := range b.GetEvents() {
				s.cfg.Canary.ObserveEvent(node, ev, s.cfg.Now())
			}
		}
		// samples are best effort: taken once, with the batch that is new
		if samples := b.GetSamples(); len(samples) > 0 && ack.Success && !ack.Duplicate && s.cfg.Samples != nil {
			s.cfg.Samples.Add(ctx, node, samples)
		}
		if err := st.Send(&fleetv1.EventAck{AckedSeq: ack.AckedSeq}); err != nil {
			return err
		}
	}
}

// ingestAction is the action stored for an event (ingest.ValidateAction:
// block, shadow, pass, error), from what libstrata encodes (tx.rs,
// encode_event):
//   - a block: BLOCK with a Block ID STR-…;
//   - an EVT-… id with LOG and rules: in shadow, a request that would have
//     been blocked (would_block, field 21, #57; a would-be block of the
//     signature pack counts too), stored as "shadow"; or rules that matched
//     below the threshold (any mode), stored as "pass", or "error" when the
//     CPU budget cut the inspection short (inspection PARTIAL: the fail
//     mode decided);
//   - an EVT-… id without any rule: an engine error or an exceeded CPU
//     budget handled by the fail mode, "error".
//
// Modules from before RV-G2-01 send neither would_block nor inspection
// (UNSPECIFIED); their EVT- events with rules stay "shadow" as before #57.
// Anything else is "" and the validator rejects it.
func ingestAction(ev *eventv1.Event) string {
	evt := strings.HasPrefix(ev.GetBlockId(), "EVT-")
	switch a := ev.GetAction(); {
	case !evt && a == eventv1.Action_ACTION_BLOCK:
		return "block"
	case evt && a == eventv1.Action_ACTION_LOG && len(ev.GetRuleIds()) > 0:
		switch {
		case ev.GetWouldBlock(), ev.GetInspection() == eventv1.Inspection_INSPECTION_UNSPECIFIED:
			return "shadow"
		case ev.GetInspection() == eventv1.Inspection_INSPECTION_PARTIAL:
			return "error"
		default:
			return "pass"
		}
	case evt && (a == eventv1.Action_ACTION_LOG || a == eventv1.Action_ACTION_ALLOW || a == eventv1.Action_ACTION_BLOCK):
		return "error"
	default:
		return ""
	}
}

func toIngest(ev *eventv1.Event, node string, now time.Time) ingest.Event {
	t := now
	if ms := ev.GetTimeUnixMs(); ms > 0 && ms < 1<<62 {
		t = time.UnixMilli(int64(ms)).UTC()
	}
	action := ingestAction(ev)
	sc := ev.GetLayerScores()
	out := ingest.Event{
		BlockID:       ev.GetBlockId(),
		Timestamp:     t,
		NodeID:        node,
		ConnectorType: "nginx",
		PolicyID:      ev.GetPolicyId(),
		PolicyVersion: ev.GetBundleVersion(),
		ClientIP:      ev.GetClientIp(),
		Identity:      ev.GetIdentity(),
		RequestID:     ev.GetRequestId(),
		HTTPMethod:    ev.GetMethod(),
		HTTPHost:      ev.GetHost(),
		HTTPPath:      ev.GetPath(),
		StatusCode:    uint16(min(ev.GetStatus(), 999)),
		Action:        action,
		ScoreProtocol: sc["protocol"],
		ScoreSQLi:     sc["sqli"],
		ScoreXSS:      sc["xss"],
		ScoreAnomaly:  sc["anomaly"],
		MatchedRules:  ev.GetRuleIds(),
		ReceivedAt:    now,
	}
	for _, m := range ev.GetMatches() {
		out.Violations = append(out.Violations, ingest.Violation{
			RuleID: m.GetRuleId(), Layer: m.GetLayer(), Field: m.GetField(), Snippet: string(m.GetSnippet()),
		})
	}
	// RV-G2-01, RV-N-01: the context, masked by the engine
	out.UserAgent, out.Referer = ev.GetUserAgent(), ev.GetReferer()
	for _, h := range ev.GetHeaders() {
		out.Headers = append(out.Headers, ingest.Header{Name: h.GetName(), Value: string(h.GetValue())})
	}
	out.Inspection = inspections[ev.GetInspection()]
	out.JA4 = ev.GetJa4()
	if costs := ev.GetRuleCosts(); len(costs) <= ingest.MaxEventRuleCosts {
		for _, c := range costs {
			out.RuleCosts = append(out.RuleCosts, ingest.RuleCost{RuleID: c.GetRuleId(), Samples: c.GetSamples(), TotalNS: c.GetTotalNs(), MaxNS: c.GetMaxNs()})
		}
	}
	return out
}

// inspections maps the event's Inspection to the stored value ("" for
// events of modules from before the field).
var inspections = map[eventv1.Inspection]string{
	eventv1.Inspection_INSPECTION_FULL:         "full",
	eventv1.Inspection_INSPECTION_PARTIAL:      "partial",
	eventv1.Inspection_INSPECTION_BODY_SKIPPED: "body_skipped",
}

// inventory is optional on old Registry implementations; production persists it.
func (s *Server) inventory(ctx context.Context, id string, n *fleetv1.NodeInfo) error {
	i := store.Inventory{AgentVersion: n.GetAgentVersion(), OS: n.GetOperatingSystem(), ABI: n.GetConnector().GetAbiVersion(), Capabilities: n.GetCapabilities()}
	if err := i.Validate(); err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	if recorder, ok := s.cfg.Registry.(interface {
		RecordInventory(context.Context, string, store.Inventory, time.Time) error
	}); ok {
		if err := recorder.RecordInventory(ctx, id, i, s.cfg.Now()); err != nil {
			return status.Error(codes.Unavailable, "inventory persistence failed")
		}
	}
	return nil
}
