package e2e

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	eventv1 "github.com/strata/strata/agent/gen/strata/event/v1"
	fleetv1 "github.com/strata/strata/agent/gen/strata/fleet/v1"
	"github.com/strata/strata/control-plane/ingest"
)

// Certs holds file paths for generated mTLS certificates.
type Certs struct {
	CA         string
	ServerCert string
	ServerKey  string
	ClientCert string
	ClientKey  string
}

// FleetIngestServer connects gRPC PushEvents directly to IngestService and ClickHouse.
type FleetIngestServer struct {
	fleetv1.UnimplementedFleetServiceServer

	addr      string
	tlsConfig *tls.Config
	ingestSvc *ingest.IngestService
	store     ingest.EventStore

	mu              sync.Mutex
	gs              *grpc.Server
	receivedBatches atomic.Uint64
	acceptedBatches atomic.Uint64
}

// PushEvents handles streaming batches from strata-agent pushers.
func (s *FleetIngestServer) PushEvents(st fleetv1.FleetService_PushEventsServer) error {
	fmt.Printf("[FleetIngestServer] PushEvents stream opened\n")
	for {
		b, err := st.Recv()
		if errors.Is(err, io.EOF) {
			fmt.Printf("[FleetIngestServer] PushEvents stream EOF\n")
			return nil
		}
		if err != nil {
			fmt.Printf("[FleetIngestServer] PushEvents Recv error: %v\n", err)
			return err
		}

		s.receivedBatches.Add(1)
		seq := b.GetSeq()
		pbEvents := b.GetEvents()
		fmt.Printf("[FleetIngestServer] Received batch seq=%d with %d events\n", seq, len(pbEvents))

		events := make([]ingest.Event, 0, len(pbEvents))
		nodeID := "node-lossless-1"

		for _, pb := range pbEvents {
			if pb.GetNodeId() != "" {
				nodeID = pb.GetNodeId()
			}
			events = append(events, protoToIngestEvent(pb, nodeID))
		}

		ack, err := s.ingestSvc.ProcessBatch(st.Context(), ingest.EventBatch{
			NodeID: nodeID,
			Seq:    seq,
			Events: events,
		})
		if err != nil {
			return fmt.Errorf("ingest process batch: %w", err)
		}

		if ack.Success {
			s.acceptedBatches.Add(1)
		}

		if err := st.Send(&fleetv1.EventAck{AckedSeq: ack.AckedSeq}); err != nil {
			return fmt.Errorf("send ack: %w", err)
		}
	}
}

func protoToIngestEvent(pb *eventv1.Event, defaultNodeID string) ingest.Event {
	t := time.UnixMilli(int64(pb.GetTimeUnixMs())).UTC()
	if t.IsZero() || pb.GetTimeUnixMs() == 0 {
		t = time.Now().UTC()
	}

	actionStr := "allow"
	switch pb.GetAction() {
	case eventv1.Action_ACTION_LOG:
		actionStr = "log"
	case eventv1.Action_ACTION_CHALLENGE:
		actionStr = "challenge"
	case eventv1.Action_ACTION_BLOCK:
		actionStr = "block"
	}

	nodeID := pb.GetNodeId()
	if nodeID == "" {
		nodeID = defaultNodeID
	}

	var violations []ingest.Violation
	for _, m := range pb.GetMatches() {
		violations = append(violations, ingest.Violation{
			RuleID:  m.GetRuleId(),
			Layer:   m.GetLayer(),
			Field:   m.GetField(),
			Snippet: string(m.GetSnippet()),
		})
	}

	scores := pb.GetLayerScores()
	var scoreProto, scoreSQL, scoreXSS, scoreAnom int32
	if scores != nil {
		scoreProto = scores["protocol"]
		scoreSQL = scores["sqli"]
		scoreXSS = scores["xss"]
		scoreAnom = scores["anomaly"]
	}

	return ingest.Event{
		BlockID:       pb.GetBlockId(),
		Timestamp:     t,
		NodeID:        nodeID,
		ConnectorType: "nginx",
		PolicyID:      pb.GetPolicyId(),
		PolicyVersion: pb.GetBundleVersion(),
		ClientIP:      pb.GetClientIp(),
		Identity:      pb.GetIdentity(),
		RequestID:     pb.GetRequestId(),
		HTTPMethod:    pb.GetMethod(),
		HTTPHost:      pb.GetHost(),
		HTTPPath:      pb.GetPath(),
		StatusCode:    uint16(pb.GetStatus()),
		Action:        actionStr,
		ScoreProtocol: scoreProto,
		ScoreSQLi:     scoreSQL,
		ScoreXSS:      scoreXSS,
		ScoreAnomaly:  scoreAnom,
		MatchedRules:  pb.GetRuleIds(),
		Violations:    violations,
		ReceivedAt:    time.Now().UTC(),
	}
}

// StartFleetIngestServer spins up an mTLS gRPC server backed by IngestService.
func StartFleetIngestServer(dir string, ingestSvc *ingest.IngestService, store ingest.EventStore) (*FleetIngestServer, Certs, error) {
	certs, serverTLS, err := makePKI(dir)
	if err != nil {
		return nil, certs, fmt.Errorf("make pki: %w", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, certs, fmt.Errorf("listen: %w", err)
	}

	srv := &FleetIngestServer{
		addr:      ln.Addr().String(),
		tlsConfig: serverTLS,
		ingestSvc: ingestSvc,
		store:     store,
	}

	gs := grpc.NewServer(grpc.Creds(credentials.NewTLS(serverTLS)))
	fleetv1.RegisterFleetServiceServer(gs, srv)

	srv.mu.Lock()
	srv.gs = gs
	srv.mu.Unlock()

	go func() { _ = gs.Serve(ln) }()

	return srv, certs, nil
}

// Addr returns the host:port the agent dials.
func (s *FleetIngestServer) Addr() string {
	return s.addr
}

// Stop cleanly terminates the gRPC server.
func (s *FleetIngestServer) Stop() {
	s.mu.Lock()
	gs := s.gs
	s.gs = nil
	s.mu.Unlock()

	if gs != nil {
		gs.Stop()
	}
}

func makePKI(dir string) (Certs, *tls.Config, error) {
	caKey, caDER, err := newCert(&x509.Certificate{
		Subject:               pkix.Name{CommonName: "Strata E2E Test CA"},
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}, nil, nil)
	if err != nil {
		return Certs{}, nil, err
	}

	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		return Certs{}, nil, err
	}

	srvKey, srvDER, err := newCert(&x509.Certificate{
		Subject:     pkix.Name{CommonName: "cp.example.test"},
		DNSNames:    []string{"cp.example.test", "localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, ca, caKey)
	if err != nil {
		return Certs{}, nil, err
	}

	cliKey, cliDER, err := newCert(&x509.Certificate{
		Subject:     pkix.Name{CommonName: "node-lossless-1"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, ca, caKey)
	if err != nil {
		return Certs{}, nil, err
	}

	caPath, err := writePEM(dir, "ca.pem", "CERTIFICATE", caDER)
	if err != nil {
		return Certs{}, nil, err
	}
	srvCertPath, err := writePEM(dir, "server.pem", "CERTIFICATE", srvDER)
	if err != nil {
		return Certs{}, nil, err
	}
	srvKeyBytes, err := marshalKey(srvKey)
	if err != nil {
		return Certs{}, nil, err
	}
	srvKeyPath, err := writePEM(dir, "server-key.pem", "EC PRIVATE KEY", srvKeyBytes)
	if err != nil {
		return Certs{}, nil, err
	}

	cliCertPath, err := writePEM(dir, "client.pem", "CERTIFICATE", cliDER)
	if err != nil {
		return Certs{}, nil, err
	}
	cliKeyBytes, err := marshalKey(cliKey)
	if err != nil {
		return Certs{}, nil, err
	}
	cliKeyPath, err := writePEM(dir, "client-key.pem", "EC PRIVATE KEY", cliKeyBytes)
	if err != nil {
		return Certs{}, nil, err
	}

	c := Certs{
		CA:         caPath,
		ServerCert: srvCertPath,
		ServerKey:  srvKeyPath,
		ClientCert: cliCertPath,
		ClientKey:  cliKeyPath,
	}

	pair, err := tls.LoadX509KeyPair(c.ServerCert, c.ServerKey)
	if err != nil {
		return Certs{}, nil, err
	}

	pool := x509.NewCertPool()
	pool.AddCert(ca)

	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{pair},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}

	return c, serverTLS, nil
}

func newCert(tmpl, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*ecdsa.PrivateKey, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	sn, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		return nil, nil, err
	}
	tmpl.SerialNumber = sn
	tmpl.NotBefore = time.Now().Add(-1 * time.Hour)
	tmpl.NotAfter = time.Now().Add(24 * time.Hour)
	if parent == nil {
		parent, parentKey = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		return nil, nil, err
	}
	return key, der, nil
}

func marshalKey(k *ecdsa.PrivateKey) ([]byte, error) {
	return x509.MarshalECPrivateKey(k)
}

func writePEM(dir, name, typ string, der []byte) (string, error) {
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		return "", err
	}
	return p, nil
}
