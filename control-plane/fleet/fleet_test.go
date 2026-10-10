package fleet

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	eventv1 "github.com/strata/strata/agent/gen/strata/event/v1"
	fleetv1 "github.com/strata/strata/agent/gen/strata/fleet/v1"
	"github.com/strata/strata/control-plane/ingest"
)

type pki struct {
	ca    *x509.Certificate
	caKey *ecdsa.PrivateKey
	pool  *x509.CertPool
}

func newPKI(t *testing.T) *pki {
	t.Helper()
	p := &pki{}
	var der []byte
	p.caKey, der = issue(t, &x509.Certificate{
		Subject: pkix.Name{CommonName: "strata lab CA"}, IsCA: true,
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true,
	}, nil, nil)
	var err error
	if p.ca, err = x509.ParseCertificate(der); err != nil {
		t.Fatal(err)
	}
	p.pool = x509.NewCertPool()
	p.pool.AddCert(p.ca)
	return p
}

func issue(t *testing.T, tmpl, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sn, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl.SerialNumber = sn
	tmpl.NotBefore, tmpl.NotAfter = time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
	if parent == nil {
		parent, parentKey = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	return key, der
}

func (p *pki) pair(t *testing.T, tmpl *x509.Certificate) tls.Certificate {
	t.Helper()
	key, der := issue(t, tmpl, p.ca, p.caKey)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// nodeCert is a client certificate for spiffe://strata/node/<id>; an empty
// id gives a certificate without the URI.
func (p *pki) nodeCert(t *testing.T, id string) tls.Certificate {
	tmpl := &x509.Certificate{Subject: pkix.Name{CommonName: "node"}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	if id != "" {
		u, _ := url.Parse(spiffePrefix + id)
		tmpl.URIs = []*url.URL{u}
	}
	return p.pair(t, tmpl)
}

func serve(t *testing.T, p *pki, in Ingester) string {
	t.Helper()
	srv := p.pair(t, &x509.Certificate{
		Subject: pkix.Name{CommonName: "cp.example.test"}, DNSNames: []string{"cp.example.test"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	gs := NewGRPCServer(&tls.Config{
		Certificates: []tls.Certificate{srv}, ClientCAs: p.pool,
		ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS13,
	}, in)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = gs.Serve(ln) }()
	t.Cleanup(gs.Stop)
	return ln.Addr().String()
}

func dial(t *testing.T, p *pki, addr string, cert *tls.Certificate) fleetv1.FleetServiceClient {
	t.Helper()
	cfg := &tls.Config{RootCAs: p.pool, ServerName: "cp.example.test", MinVersion: tls.VersionTLS13}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(cfg)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return fleetv1.NewFleetServiceClient(conn)
}

func event(id string) *eventv1.Event {
	return &eventv1.Event{
		BlockId: id, TimeUnixMs: uint64(time.Now().UnixMilli()), NodeId: "worker-claims-this",
		PolicyId: "example-api", BundleVersion: 3, ClientIp: "192.0.2.10", Method: "POST",
		Host: "api.example.test", Path: "/v1/items", Status: 403, Action: eventv1.Action_ACTION_BLOCK,
		LayerScores: map[string]int32{"sqli": 45, "anomaly": 45}, RuleIds: []uint32{942100},
		Matches: []*eventv1.Match{{RuleId: 942100, Layer: "sqli", Field: "ARGS:q", Snippet: []byte("' OR 1=1 --")}},
	}
}

func push(t *testing.T, cl fleetv1.FleetServiceClient, batches ...*fleetv1.EventBatch) ([]uint64, error) {
	t.Helper()
	st, err := cl.PushEvents(context.Background())
	if err != nil {
		return nil, err
	}
	var acks []uint64
	for _, b := range batches {
		if err := st.Send(b); err != nil {
			_, err = st.Recv()
			return acks, err
		}
		a, err := st.Recv()
		if err != nil {
			return acks, err
		}
		acks = append(acks, a.GetAckedSeq())
	}
	return acks, st.CloseSend()
}

func TestPushEventsToIngest(t *testing.T) {
	p := newPKI(t)
	store := ingest.NewMockEventStore()
	svc := ingest.NewIngestService(store, ingest.DefaultBatcherConfig(), time.Hour)
	t.Cleanup(func() { _ = svc.Close(context.Background()) })
	addr := serve(t, p, svc)
	cert := p.nodeCert(t, "node-1")
	cl := dial(t, p, addr, &cert)

	acks, err := push(t, cl,
		&fleetv1.EventBatch{Seq: 1, Events: []*eventv1.Event{event("STR-8F3K-Q2VD-7XNM-A1PC")}},
		&fleetv1.EventBatch{Seq: 2, Events: []*eventv1.Event{event("STR-3B9Y-K8P2-WM4C-9D0R")}},
		// Resent after a reconnect: dropped, but acked.
		&fleetv1.EventBatch{Seq: 1, Events: []*eventv1.Event{event("STR-8F3K-Q2VD-7XNM-A1PC")}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(acks) != 3 || acks[0] != 1 || acks[1] != 2 {
		t.Fatalf("acks %v", acks)
	}
	if err := svc.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st := svc.Stats(); st.TotalBatchesAccepted != 2 || st.TotalBatchesDropped != 1 {
		t.Fatalf("stats %+v", st)
	}
	ev, err := store.GetEvent(context.Background(), "STR-8F3K-Q2VD-7XNM-A1PC")
	if err != nil {
		t.Fatal(err)
	}
	if ev.NodeID != "node-1" || ev.Action != "block" || ev.ScoreSQLi != 45 || ev.PolicyVersion != 3 ||
		len(ev.Violations) != 1 || ev.Violations[0].Snippet != "' OR 1=1 --" {
		t.Fatalf("stored %+v", ev)
	}
}

func TestPushEventsNeedsNodeIdentity(t *testing.T) {
	p := newPKI(t)
	addr := serve(t, p, ingest.NewIngestService(ingest.NewMockEventStore(), ingest.DefaultBatcherConfig(), time.Hour))

	noID := p.nodeCert(t, "")
	_, err := push(t, dial(t, p, addr, &noID), &fleetv1.EventBatch{Seq: 1})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("certificate without node id: %v", err)
	}
	if _, err := push(t, dial(t, p, addr, nil), &fleetv1.EventBatch{Seq: 1}); err == nil {
		t.Fatal("stream without client certificate accepted")
	}
	other := newPKI(t)
	foreign := other.nodeCert(t, "node-1")
	if _, err := push(t, dial(t, p, addr, &foreign), &fleetv1.EventBatch{Seq: 1}); err == nil {
		t.Fatal("certificate from another CA accepted")
	}
}

func TestPushEventsRejectsHugeBatch(t *testing.T) {
	p := newPKI(t)
	addr := serve(t, p, ingest.NewIngestService(ingest.NewMockEventStore(), ingest.DefaultBatcherConfig(), time.Hour))
	cert := p.nodeCert(t, "node-1")
	b := &fleetv1.EventBatch{Seq: 1}
	for i := 0; i <= MaxBatchEvents; i++ {
		b.Events = append(b.Events, &eventv1.Event{BlockId: "STR-0"})
	}
	if _, err := push(t, dial(t, p, addr, &cert), b); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("huge batch: %v", err)
	}
}
