package e2e

// W07-G1-01: commands from the admin API reach a real agent; a short node
// certificate is renewed without losing the connection; a cut of the
// network to the control plane (toxiproxy) heals by itself.

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	eventv1 "github.com/strata/strata/agent/gen/strata/event/v1"
)

// writeControl writes a control file naming bundle-1.sbn (layout 1,
// generation 2), as an installed bundle leaves it.
func writeControl(t *testing.T, path string) {
	t.Helper()
	b := make([]byte, 4096)
	copy(b, "STRCTL1\x00")
	binary.LittleEndian.PutUint32(b[8:], 1)
	binary.LittleEndian.PutUint64(b[16:], 2)
	binary.LittleEndian.PutUint64(b[24:], 1)
	binary.LittleEndian.PutUint16(b[64:], uint16(len("bundle-1.sbn")))
	copy(b[66:], "bundle-1.sbn")
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// forced reads the force-shadow block: flags and policy names.
func forced(path string) (bool, []string) {
	b, err := os.ReadFile(path)
	if err != nil || len(b) != 4096 {
		return false, nil
	}
	var names []string
	for i := 0; i < int(binary.LittleEndian.Uint32(b[328:])) && i < 32; i++ {
		names = append(names, string(bytes.TrimRight(b[336+i*56:336+(i+1)*56], "\x00")))
	}
	return binary.LittleEndian.Uint32(b[324:])&1 != 0, names
}

type commandJSON struct {
	ID     string `json:"id"`
	NodeID string `json:"node_id"`
	State  string `json:"state"`
	Error  string `json:"error"`
	Output string `json:"output"`
}

func (e *fleetEnv) command(t *testing.T, id string) commandJSON {
	t.Helper()
	var out struct {
		Command commandJSON `json:"command"`
	}
	if c := e.call(t, "viewer", http.MethodGet, "/v1/commands/"+id, "", &out); c != http.StatusOK {
		t.Fatalf("GET /v1/commands/%s: %d", id, c)
	}
	return out.Command
}

func (e *fleetEnv) diagnostics(t *testing.T, nodeID string) commandJSON {
	t.Helper()
	var out struct {
		Command commandJSON `json:"command"`
	}
	if c := e.call(t, "admin", http.MethodPost, "/v1/nodes/"+nodeID+":collectDiagnostics", `{}`, &out); c != http.StatusOK {
		t.Fatalf("collect diagnostics: %d", c)
	}
	var cmd commandJSON
	waitFor(t, "diagnostics answered", 15*time.Second, func() bool {
		cmd = e.command(t, out.Command.ID)
		return cmd.State == "DONE" || cmd.State == "FAILED"
	})
	if cmd.State != "DONE" {
		t.Fatalf("diagnostics: %+v", cmd)
	}
	return cmd
}

func TestForceShadowAndDiagnosticsReachTheAgent(t *testing.T) {
	e := startFleet(t)
	bin := buildAgentBinary(t)
	p := &platform{fleetEnv: e}
	nd := p.enrollNodes(t, bin, 1)[0]
	writeControl(t, nd.control)
	nd.start(t, bin, e.addr)
	waitFor(t, "online", 30*time.Second, func() bool { return e.node(t, nd.id).Online })

	var fs struct {
		Commands []commandJSON `json:"commands"`
	}
	if c := e.call(t, "viewer", http.MethodPost, "/v1/nodes:forceShadow", `{"node_id":"`+nd.id+`","policy_id":"example-api","duration_seconds":3}`, nil); c != http.StatusForbidden {
		t.Fatalf("viewer forces shadow: %d", c)
	}
	start := time.Now()
	if c := e.call(t, "operator", http.MethodPost, "/v1/nodes:forceShadow", `{"node_id":"`+nd.id+`","policy_id":"example-api","duration_seconds":4}`, &fs); c != http.StatusOK || len(fs.Commands) != 1 {
		t.Fatalf("force shadow: %d %+v", c, fs)
	}
	took := waitFor(t, "control file forced", 5*time.Second, func() bool {
		_, names := forced(nd.control)
		return len(names) == 1 && names[0] == "example-api"
	})
	t.Logf("force shadow in the control file %s after the API call", took.Round(time.Millisecond))
	waitFor(t, "command DONE", 5*time.Second, func() bool { return e.command(t, fs.Commands[0].ID).State == "DONE" })

	// Diagnostics while forced: they show it, and nothing secret.
	d := e.diagnostics(t, nd.id)
	var diag map[string]any
	if err := json.Unmarshal([]byte(d.Output), &diag); err != nil {
		t.Fatalf("diagnostics output: %v: %s", err, d.Output)
	}
	if diag["node_id"] != nd.id || !strings.Contains(d.Output, "example-api") {
		t.Fatalf("diagnostics: %s", d.Output)
	}
	key, _ := os.ReadFile(filepath.Join(nd.identity, "node.key"))
	if strings.Contains(d.Output, "PRIVATE") || strings.Contains(d.Output, nd.identity) || bytes.Contains([]byte(d.Output), key[40:80]) {
		t.Fatalf("diagnostics leak identity data: %s", d.Output)
	}

	// The deadline passes: the agent clears the block.
	waitFor(t, "force shadow expired", 4*time.Second+3*time.Second-time.Since(start), func() bool {
		_, names := forced(nd.control)
		return len(names) == 0
	})

	// Every policy, through the node's group; refused for a route.
	if c := e.call(t, "operator", http.MethodPost, "/v1/nodes:forceShadow", `{"group_id":"lab","duration_seconds":60}`, &fs); c != http.StatusOK {
		t.Fatalf("group force shadow: %d", c)
	}
	waitFor(t, "every policy forced", 5*time.Second, func() bool { all, _ := forced(nd.control); return all })

	// Survives a restart of the agent with its deadline.
	_ = nd.proc.stop(5 * time.Second)
	nd.start(t, bin, e.addr)
	time.Sleep(2 * time.Second)
	if all, _ := forced(nd.control); !all {
		t.Fatal("force shadow lost across an agent restart")
	}

	// The audit log names who did it.
	entries, _ := e.st.AuditEntries(context.Background(), 20)
	found := false
	for _, a := range entries {
		if strings.Contains(a.Action, "ForceShadow") && a.Actor != "" && strings.HasPrefix(a.Resource, "groups/lab") {
			found = true
		}
	}
	if !found {
		t.Error("no audit entry for the group force shadow")
	}
}

// A 3-minute certificate is renewed at about a third of its life left;
// the agent then dials again with it, so the calls that follow (events,
// commands) are accepted instead of refused as superseded.
func TestShortCertificateRenewedWithoutLosingTheConnection(t *testing.T) {
	if testing.Short() {
		t.Skip("takes about 3 minutes")
	}
	e := startFleetWith(t, 3*time.Minute)
	bin := buildAgentBinary(t)
	p := &platform{fleetEnv: e}
	nd := p.enrollNodes(t, bin, 1)[0]
	writeControl(t, nd.control)
	before, err := e.st.GetNode(context.Background(), nd.id)
	if err != nil {
		t.Fatal(err)
	}
	nd.start(t, bin, e.addr)
	waitFor(t, "online", 30*time.Second, func() bool { return e.node(t, nd.id).Online })

	var after time.Time
	took := waitFor(t, "renewal", 3*time.Minute, func() bool {
		n, err := e.st.GetNode(context.Background(), nd.id)
		if err == nil && n.CertSerial != before.CertSerial {
			after = *n.CertNotAfter
			return true
		}
		return false
	})
	left := time.Until(*before.CertNotAfter)
	t.Logf("renewed %s after start, %s before the old certificate expired; new one until %s", took.Round(time.Second), left.Round(time.Second), after.Format(time.TimeOnly))
	if left < 30*time.Second || left > 100*time.Second {
		t.Errorf("renewed with %s left, want about a third of 4 min (80 s)", left)
	}

	// New calls after the renewal: an event and a command.
	time.Sleep(2 * time.Second)
	w, err := newLosslessWorker(filepath.Join(nd.dir, "events.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if err := w.send(&eventv1.Event{BlockId: "STR-RNEW-0000-0000-0001", TimeUnixMs: uint64(time.Now().UnixMilli()), NodeId: nd.id,
		PolicyId: "example-api", Method: "GET", Host: "api.example.test", Path: "/", Status: 403, Action: eventv1.Action_ACTION_BLOCK}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "event stored after renewal", 30*time.Second, func() bool {
		ev, err := e.events.GetEvent(context.Background(), "STR-RNEW-0000-0000-0001")
		return err == nil && ev != nil
	})
	e.diagnostics(t, nd.id)
	if !e.node(t, nd.id).Online {
		t.Fatal("offline after the renewal")
	}
	logs := nd.proc.logBuf.String()
	if strings.Contains(logs, "superseded") {
		t.Fatalf("agent used the old certificate after the renewal:\n%s", logs)
	}
	if !strings.Contains(logs, "closing connections made with the old certificate") {
		t.Errorf("no reconnection after the renewal:\n%s", logs)
	}
}

// toxiproxy between the agent and the control plane: the network is cut
// for STRATA_E2E_OUTAGE (default 5m) and comes back; the agent connects
// again by itself.
func TestNetworkOutageHeals(t *testing.T) {
	if testing.Short() {
		t.Skip("network outage test")
	}
	outage := 5 * time.Minute
	if v := os.Getenv("STRATA_E2E_OUTAGE"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			t.Fatalf("STRATA_E2E_OUTAGE: %v", err)
		}
		outage = d
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

	proxy.enable(t, "cp", false)
	cut := time.Now()
	took := waitFor(t, "offline", 45*time.Second, func() bool { return !e.node(t, nd.id).Online })
	t.Logf("network cut: node offline after %s; cut lasts %s", took.Round(time.Millisecond), outage)
	time.Sleep(outage - time.Since(cut))
	if e.node(t, nd.id).Online {
		t.Fatal("online while the network is cut")
	}
	proxy.enable(t, "cp", true)
	back := time.Now()
	for !e.node(t, nd.id).Online {
		if time.Since(back) > 90*time.Second {
			t.Fatalf("not online 90 s after the network came back; agent log:\n%s", nd.proc.logBuf.String())
		}
		time.Sleep(100 * time.Millisecond)
	}
	took = time.Since(back)
	t.Logf("network back after %s: node online again %s later", time.Since(cut).Round(time.Second), took.Round(time.Millisecond))
	// and the stream works: a command goes through
	e.diagnostics(t, nd.id)
}

type toxiproxy struct{ api, name string }

// startToxiproxy runs toxiproxy on the host network (the control plane of
// the test listens on 127.0.0.1).
func startToxiproxy(t *testing.T) *toxiproxy {
	t.Helper()
	name := fmt.Sprintf("strata-e2e-toxi-%d", time.Now().UnixNano()%1000000)
	port := freePort(t)
	out, err := exec.Command("docker", "run", "-d", "--rm", "--name", name, "--network", "host",
		"ghcr.io/shopify/toxiproxy:2.12.0", "-host", "127.0.0.1", "-port", fmt.Sprint(port)).CombinedOutput()
	if err != nil {
		t.Fatalf("start toxiproxy: %v: %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "stop", "-t", "2", name).Run() })
	tp := &toxiproxy{api: fmt.Sprintf("http://127.0.0.1:%d", port), name: name}
	waitFor(t, "toxiproxy up", 60*time.Second, func() bool {
		r, err := http.Get(tp.api + "/version")
		if err == nil {
			r.Body.Close()
		}
		return err == nil && r.StatusCode == http.StatusOK
	})
	return tp
}

func (tp *toxiproxy) do(t *testing.T, method, path, body string) {
	t.Helper()
	req, _ := http.NewRequest(method, tp.api+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	if r.StatusCode >= 300 {
		t.Fatalf("toxiproxy %s %s: %d", method, path, r.StatusCode)
	}
}

// create proxies a free local port to upstream and returns that address.
func (tp *toxiproxy) create(t *testing.T, name, upstream string) string {
	t.Helper()
	listen := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	tp.do(t, http.MethodPost, "/proxies", fmt.Sprintf(`{"name":%q,"listen":%q,"upstream":%q,"enabled":true}`, name, listen, upstream))
	return listen
}

// enable turns the proxy on or off; off closes its connections and
// refuses new ones.
func (tp *toxiproxy) enable(t *testing.T, name string, on bool) {
	t.Helper()
	tp.do(t, http.MethodPost, "/proxies/"+name, fmt.Sprintf(`{"enabled":%t}`, on))
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}
