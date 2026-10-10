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
	Now          func() time.Time
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
	ctx, done := s.cfg.Presence.Attach(st.Context(), id, KindConnect)
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
		case err := <-errc:
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		case m := <-msgs:
			switch msg := m.GetMsg().(type) {
			case *fleetv1.AgentMessage_Hello:
				greeted = true
				ni := msg.Hello.GetNode()
				v := int64(msg.Hello.GetActiveBundleVersion())
				s.seen(ctx, id, clean(ni.GetHostname(), 253), clean(ni.GetConnector().GetProxyVersion(), 64),
					clean(ni.GetConnector().GetModuleVersion(), 64), &v)
			case *fleetv1.AgentMessage_Heartbeat:
				if !greeted {
					return status.Error(codes.InvalidArgument, "the stream must start with Hello")
				}
				v := int64(msg.Heartbeat.GetActiveBundleVersion())
				s.seen(ctx, id, "", "", "", &v)
			default:
				if !greeted {
					return status.Error(codes.InvalidArgument, "the stream must start with Hello")
				}
				// BundleStatus and CommandResult arrive with W05-G1-01.
			}
		}
	}
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
		if len(b.GetEvents()) > MaxBatchEvents {
			return status.Errorf(codes.InvalidArgument, "batch of %d events, at most %d", len(b.GetEvents()), MaxBatchEvents)
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
		if err := st.Send(&fleetv1.EventAck{AckedSeq: ack.AckedSeq}); err != nil {
			return err
		}
	}
}

var actions = map[eventv1.Action]string{
	eventv1.Action_ACTION_ALLOW:     "allow",
	eventv1.Action_ACTION_LOG:       "log",
	eventv1.Action_ACTION_CHALLENGE: "challenge",
	eventv1.Action_ACTION_BLOCK:     "block",
}

func toIngest(ev *eventv1.Event, node string, now time.Time) ingest.Event {
	t := now
	if ms := ev.GetTimeUnixMs(); ms > 0 && ms < 1<<62 {
		t = time.UnixMilli(int64(ms)).UTC()
	}
	action := actions[ev.GetAction()] // "" for unknown: the validator rejects it
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
	return out
}
