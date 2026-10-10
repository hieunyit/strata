// Package fleet serves strata.fleet.v1.FleetService for strata-agent.
// For now only PushEvents is implemented: batches go to the ingest
// service, which drops batches whose seq is not above the last one
// committed for the node (nginx-module.md › "Giao thức gRPC agent ↔
// control plane").
//
// The node is identified by its mTLS client certificate
// (spiffe://strata/node/<node_id>), never by the node_id an event
// carries.
package fleet

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	eventv1 "github.com/strata/strata/agent/gen/strata/event/v1"
	fleetv1 "github.com/strata/strata/agent/gen/strata/fleet/v1"
	"github.com/strata/strata/control-plane/ingest"
)

const (
	spiffePrefix = "spiffe://strata/node/"
	// MaxBatchEvents bounds one EventBatch; the agent sends at most 500.
	MaxBatchEvents = 5000
	maxNodeID      = 128
)

// Ingester is the part of ingest.IngestService the server uses.
type Ingester interface {
	ProcessBatch(ctx context.Context, batch ingest.EventBatch) (*ingest.EventAck, error)
}

// Server implements FleetService.
type Server struct {
	fleetv1.UnimplementedFleetServiceServer
	ingest Ingester
}

// NewServer returns a FleetService backed by in.
func NewServer(in Ingester) *Server { return &Server{ingest: in} }

// NewGRPCServer returns a gRPC server with mTLS and FleetService
// registered.
func NewGRPCServer(tlsCfg *tls.Config, in Ingester) *grpc.Server {
	gs := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsCfg)))
	fleetv1.RegisterFleetServiceServer(gs, NewServer(in))
	return gs
}

// ServerTLS loads the server certificate and the CA that signs node
// certificates. TLS 1.3 and a client certificate are required.
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
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// NodeID returns the node id of the verified client certificate.
func NodeID(ctx context.Context) (string, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "", errors.New("no peer")
	}
	info, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(info.State.VerifiedChains) == 0 || len(info.State.VerifiedChains[0]) == 0 {
		return "", errors.New("no verified client certificate")
	}
	for _, u := range info.State.VerifiedChains[0][0].URIs {
		s := u.String()
		if id, ok := strings.CutPrefix(s, spiffePrefix); ok && id != "" && len(id) <= maxNodeID && !strings.Contains(id, "/") {
			return id, nil
		}
	}
	return "", errors.New("client certificate has no spiffe://strata/node/ id")
}

// PushEvents commits each batch through the ingest service and acks it.
func (s *Server) PushEvents(st fleetv1.FleetService_PushEventsServer) error {
	node, err := NodeID(st.Context())
	if err != nil {
		return status.Error(codes.Unauthenticated, err.Error())
	}
	for {
		b, err := st.Recv()
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
		ack, err := s.ingest.ProcessBatch(st.Context(), ingest.EventBatch{NodeID: node, Seq: b.GetSeq(), Events: events})
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
