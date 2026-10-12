package e2e

// W08-G2-01: with toxiproxy injecting latency, packet slicing and
// intermittent cuts between an agent and the control plane, no event is
// lost and no bundle is delivered corrupt.

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	eventv1 "github.com/strata/strata/agent/gen/strata/event/v1"
	"github.com/strata/strata/agent/pkg/bundlefmt"
)

// toxic adds a toxic to a proxy (latency, slicer, ...).
func (tp *toxiproxy) toxic(t *testing.T, proxy, body string) {
	t.Helper()
	tp.do(t, http.MethodPost, "/proxies/"+proxy+"/toxics", body)
}

// degrade makes the link slow and choppy: latency with jitter, and the
// stream sliced into small pieces with a delay (a stand-in for packet loss
// and fragmentation on top of the on/off cuts the test also does).
func (tp *toxiproxy) degrade(t *testing.T, proxy string) {
	t.Helper()
	tp.toxic(t, proxy, `{"name":"lat","type":"latency","attributes":{"latency":120,"jitter":80}}`)
	tp.toxic(t, proxy, `{"name":"slice","type":"slicer","attributes":{"average_size":128,"size_variation":64,"delay":5}}`)
}

// Events queued while the link is flapping are all delivered once it heals.
func TestEventsSurviveNetworkFaults(t *testing.T) {
	if testing.Short() {
		t.Skip("network fault e2e (docker)")
	}
	e := startFleet(t)
	bin := buildAgentBinary(t)
	p := &platform{fleetEnv: e}
	nd := p.enrollNodes(t, bin, 1)[0]
	writeControl(t, nd.control)

	proxy := startToxiproxy(t)
	listen := proxy.create(t, "cp", e.addr)
	nd.start(t, bin, listen)
	waitFor(t, "online through the proxy", 30*time.Second, func() bool { return e.node(t, nd.id).Online })
	// latency (not slicer) plus the on/off cuts below: delay and dropped
	// in-flight events, which the agent must resend without loss.
	proxy.toxic(t, "cp", `{"name":"lat","type":"latency","attributes":{"latency":120,"jitter":80}}`)

	w, err := newLosslessWorker(filepath.Join(nd.dir, "events.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	const n = 100
	ids := make([]string, n)
	// Feed events while the link is cut and restored twice. The worker talks
	// to the agent over a local socket, so sends keep succeeding; the agent
	// spools and resends what it cannot deliver yet.
	go func() {
		for i := range n {
			if i == 20 {
				proxy.enable(t, "cp", false)
			}
			if i == 40 {
				proxy.enable(t, "cp", true)
			}
			if i == 60 {
				proxy.enable(t, "cp", false)
			}
			if i == 80 {
				proxy.enable(t, "cp", true)
			}
			// Crockford base32 (no I/L/O/U); the ingest validates the format.
			id := fmt.Sprintf("STR-FT00-0000-0000-%04d", i)
			ids[i] = id
			_ = w.send(&eventv1.Event{
				BlockId: id, TimeUnixMs: uint64(time.Now().UnixMilli()), NodeId: nd.id,
				PolicyId: "example-api", Method: "GET", Host: "api.example.test", Path: "/",
				Status: 403, Action: eventv1.Action_ACTION_BLOCK,
			})
			time.Sleep(20 * time.Millisecond)
		}
	}()

	// Every event eventually reaches the control plane: none is lost.
	deadline := time.Now().Add(120 * time.Second)
	for {
		missing := 0
		for _, id := range ids {
			if id == "" {
				missing++
				continue
			}
			if ev, err := e.events.GetEvent(context.Background(), id); err != nil || ev == nil {
				missing++
			}
		}
		if missing == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Logf("agent log:\n%s", nd.proc.logBuf.String())
			t.Fatalf("%d/%d events still missing after the link healed", missing, n)
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Logf("all %d events delivered across two network cuts", n)
}

// A bundle rolled out while the link is slow and cut once is downloaded,
// verified and activated — never corrupt.
func TestBundleRolloutSurvivesNetworkFaults(t *testing.T) {
	if testing.Short() {
		t.Skip("network fault e2e (docker)")
	}
	p := startPlatform(t)
	bin := buildAgentBinary(t)
	nd := p.enrollNodes(t, bin, 1)[0]

	proxy := startToxiproxy(t)
	listen := proxy.create(t, "cp", p.addr)
	nd.start(t, bin, listen)
	waitFor(t, "online through the proxy", 30*time.Second, func() bool { return p.node(t, nd.id).Online })
	proxy.degrade(t, "cp")

	// Cut the link once while the bundle is being fetched; the resumable
	// FetchBundle picks up where it stopped.
	go func() {
		time.Sleep(1500 * time.Millisecond)
		proxy.enable(t, "cp", false)
		time.Sleep(3 * time.Second)
		proxy.enable(t, "cp", true)
	}()

	r1 := p.deploy(t, "MODE_SHADOW")
	waitFor(t, "rollout done through a flaky link", 180*time.Second, func() bool {
		return p.rollout(t, r1).Rollout.State == "DONE"
	})

	if v := nd.controlVersion(); v != 1 {
		t.Fatalf("control file names %d, want 1", v)
	}
	data, err := os.ReadFile(filepath.Join(nd.bundles, "bundle-1.sbn"))
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	if _, err := bundlefmt.Verify(data, p.pub); err != nil {
		t.Fatalf("delivered bundle is corrupt: %v", err)
	}
	t.Logf("bundle %d bytes downloaded, verified and activated across a cut", len(data))
}
