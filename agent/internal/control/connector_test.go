package control

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	fleetv1 "github.com/strata/strata/agent/gen/strata/fleet/v1"
)

type helloFleet struct {
	fleetv1.UnimplementedFleetServiceServer
	mu     sync.Mutex
	hellos []*fleetv1.Hello
}

func (f *helloFleet) Connect(st fleetv1.FleetService_ConnectServer) error {
	for {
		m, err := st.Recv()
		if err != nil {
			return nil
		}
		if h := m.GetHello(); h != nil {
			f.mu.Lock()
			f.hellos = append(f.hellos, h)
			f.mu.Unlock()
		}
	}
}

func (f *helloFleet) versions() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, h := range f.hellos {
		out = append(out, h.GetNode().GetConnector().GetProxyVersion())
	}
	return out
}

// W07-F-01: Hello carries the connector versions; when they change (NGINX
// started after the agent, or was upgraded), the agent reconnects to send
// them.
func TestHelloReportsConnectorVersions(t *testing.T) {
	f := &helloFleet{}
	var ver atomic.Value
	ver.Store("")
	c := New(client(t, f), Options{Heartbeat: 20 * time.Millisecond, BackoffMin: time.Millisecond, BackoffMax: time.Millisecond,
		Node: &fleetv1.NodeInfo{Hostname: "edge-01", Connector: &fleetv1.Connector{Type: "nginx"}},
		Connector: func() *fleetv1.Connector {
			v := ver.Load().(string)
			if v == "" {
				return nil
			}
			return &fleetv1.Connector{ProxyVersion: v, ModuleVersion: "0.1.0", AbiVersion: 0x10001}
		}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = c.Run(ctx) }()
	eventually(t, "first hello", func() bool { return len(f.versions()) == 1 })
	ver.Store("1.30.5")
	eventually(t, "hello with the version", func() bool {
		v := f.versions()
		return len(v) >= 2 && v[len(v)-1] == "1.30.5"
	})
	time.Sleep(100 * time.Millisecond)
	if n := len(f.versions()); n != 2 {
		t.Fatalf("%d hellos, want 2 (no reconnect while the version stays)", n)
	}
	f.mu.Lock()
	h := f.hellos[1]
	f.mu.Unlock()
	if h.GetNode().GetConnector().GetType() != "nginx" || h.GetNode().GetHostname() != "edge-01" || h.GetNode().GetConnector().GetAbiVersion() != 0x10001 {
		t.Fatalf("%v", h)
	}
}
