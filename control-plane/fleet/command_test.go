package fleet

import (
	"strings"
	"testing"
	"time"

	fleetv1 "github.com/strata/strata/agent/gen/strata/fleet/v1"
	"github.com/strata/strata/control-plane/store"
)

func TestClearCommandMessage(t *testing.T) {
	m := CommandMessage(store.Command{ID: "cmd-x", Kind: store.CommandClearShadow, PolicyID: "example-api"})
	fs := m.GetCommand().GetForceShadow()
	if !fs.GetClear() || fs.GetPolicyId() != "example-api" || fs.GetDurationSeconds() != 0 {
		t.Fatalf("%v", m)
	}
}

// W07-G1-01: a pending command reaches the node's open stream once; the
// node's answer closes it; answers for other nodes' or closed commands,
// and oversized output, change nothing they should not.
func TestCommandsReachTheStreamAndResultsCloseThem(t *testing.T) {
	e := newEnrollEnv(t)
	e.reg.addToken("tok-a", time.Hour)
	e.reg.addToken("tok-b", time.Hour)
	ra, pairA, err := e.enroll(t, "tok-a")
	if err != nil {
		t.Fatal(err)
	}
	rb, _, err := e.enroll(t, "tok-b")
	if err != nil {
		t.Fatal(err)
	}
	a, b := ra.GetNodeId(), rb.GetNodeId()
	now := time.Now()
	e.reg.mu.Lock()
	e.reg.commands = []store.Command{
		{ID: "cmd-1", NodeID: a, Kind: store.CommandForceShadow, PolicyID: "example-api", DurationSeconds: 60, State: store.CommandPending, ExpiresAt: now.Add(time.Minute)},
		{ID: "cmd-2", NodeID: b, Kind: store.CommandDiagnostics, State: store.CommandPending, ExpiresAt: now.Add(time.Minute)},
		{ID: "cmd-3", NodeID: a, Kind: store.CommandDiagnostics, State: store.CommandPending, ExpiresAt: now.Add(-time.Second)},
	}
	e.reg.mu.Unlock()

	st, cancel := connect(t, dial(t, e.p, e.addr, &pairA), true)
	defer cancel()
	eventually(t, "online", func() bool { return e.srv.Presence().Connected(a) })
	cmds := NewCommands(e.reg, e.srv.Presence())
	if err := cmds.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	m, err := st.Recv()
	if err != nil {
		t.Fatal(err)
	}
	fs := m.GetCommand().GetForceShadow()
	if m.GetCommand().GetId() != "cmd-1" || fs.GetPolicyId() != "example-api" || fs.GetDurationSeconds() != 60 {
		t.Fatalf("got %v", m)
	}
	if e.reg.command("cmd-1").State != store.CommandSent || e.reg.command("cmd-2").State != store.CommandPending ||
		e.reg.command("cmd-3").State != store.CommandExpired {
		t.Fatalf("states %v", e.reg.commands)
	}
	// Sent once only.
	if err := cmds.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}

	send := func(r *fleetv1.CommandResult) {
		t.Helper()
		if err := st.Send(&fleetv1.AgentMessage{Msg: &fleetv1.AgentMessage_CommandResult{CommandResult: r}}); err != nil {
			t.Fatal(err)
		}
	}
	send(&fleetv1.CommandResult{CommandId: "cmd-2", Ok: true}) // another node's command
	send(&fleetv1.CommandResult{CommandId: "cmd-1", Ok: false, Error: "no control file\x00 yet", Output: strings.Repeat("x", maxCommandOutput+1)})
	eventually(t, "result stored", func() bool { return e.reg.command("cmd-1").State == store.CommandFailed })
	c := e.reg.command("cmd-1")
	if c.Error != "no control file yet" || c.Output != "" {
		t.Fatalf("stored %+v", c)
	}
	if e.reg.command("cmd-2").State != store.CommandPending {
		t.Fatal("a node closed another node's command")
	}
	send(&fleetv1.CommandResult{CommandId: "cmd-1", Ok: true}) // closed already
	time.Sleep(100 * time.Millisecond)
	if e.reg.command("cmd-1").State != store.CommandFailed {
		t.Fatal("a closed command was answered again")
	}
}

func TestKillSwitchCommandMessages(t *testing.T) {
	d := CommandMessage(store.Command{ID: "a", Kind: store.CommandDisableRules, RuleIDs: []int32{942100, 0}}).GetCommand().GetDisableRules()
	if d.GetReplace() || len(d.GetRuleIds()) != 1 || d.GetRuleIds()[0] != 942100 {
		t.Fatalf("%v", d)
	}
	if !CommandMessage(store.Command{Kind: store.CommandSetRules}).GetCommand().GetDisableRules().GetReplace() {
		t.Fatal("set: not replace")
	}
	e := CommandMessage(store.Command{Kind: store.CommandEnableRules}).GetCommand().GetEnableRules()
	if !e.GetAll() {
		t.Fatalf("enable without ids is not all: %v", e)
	}
	e = CommandMessage(store.Command{Kind: store.CommandEnableRules, RuleIDs: []int32{941100}}).GetCommand().GetEnableRules()
	if e.GetAll() || e.GetRuleIds()[0] != 941100 {
		t.Fatalf("%v", e)
	}
}
