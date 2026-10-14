package fleet

import (
	"context"
	"log"
	"time"

	fleetv1 "github.com/strata/strata/agent/gen/strata/fleet/v1"
	"github.com/strata/strata/control-plane/store"
)

// CommandStore is the part of store.Store commands use.
type CommandStore interface {
	PendingCommands(ctx context.Context, nodes []string, now time.Time) ([]store.Command, error)
	MarkCommandSent(ctx context.Context, id string, now time.Time) error
}

// Commands sends the pending commands of the nodes connected to this
// control plane (each replica sends to its own streams), every second and
// when kicked by the admin API.
type Commands struct {
	Store    CommandStore
	Presence *Presence
	Now      func() time.Time
	kick     chan struct{}
}

// NewCommands returns a dispatcher; call Run.
func NewCommands(st CommandStore, p *Presence) *Commands {
	return &Commands{Store: st, Presence: p, Now: time.Now, kick: make(chan struct{}, 1)}
}

// Kick asks for a dispatch now.
func (c *Commands) Kick() {
	select {
	case c.kick <- struct{}{}:
	default:
	}
}

// Run dispatches until ctx ends.
func (c *Commands) Run(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-c.kick:
		}
		if err := c.Tick(ctx); err != nil && ctx.Err() == nil {
			log.Printf("[WARN] fleet: commands: %v", err)
		}
	}
}

// Tick sends what is pending for the connected nodes.
func (c *Commands) Tick(ctx context.Context) error {
	now := c.Now()
	cmds, err := c.Store.PendingCommands(ctx, c.Presence.ConnectedNodes(), now)
	if err != nil {
		return err
	}
	for _, cmd := range cmds {
		if !c.Presence.Notify(cmd.NodeID, CommandMessage(cmd)) {
			continue // stream full or gone: next tick
		}
		if err := c.Store.MarkCommandSent(ctx, cmd.ID, now); err != nil {
			return err
		}
	}
	return nil
}

// CommandMessage is the ControlMessage for cmd.
func CommandMessage(cmd store.Command) *fleetv1.ControlMessage {
	pc := &fleetv1.Command{Id: cmd.ID}
	switch cmd.Kind {
	case store.CommandForceShadow:
		pc.Action = &fleetv1.Command_ForceShadow{ForceShadow: &fleetv1.ForceShadow{
			PolicyId: cmd.PolicyID, DurationSeconds: uint32(cmd.DurationSeconds),
		}}
	case store.CommandClearShadow:
		pc.Action = &fleetv1.Command_ForceShadow{ForceShadow: &fleetv1.ForceShadow{PolicyId: cmd.PolicyID, Clear: true}}
	case store.CommandDiagnostics:
		pc.Action = &fleetv1.Command_Diagnostics{Diagnostics: &fleetv1.CollectDiagnostics{}}
	case store.CommandDisableRules, store.CommandSetRules:
		pc.Action = &fleetv1.Command_DisableRules{DisableRules: &fleetv1.DisableRules{
			RuleIds: ruleIDs(cmd.RuleIDs), Replace: cmd.Kind == store.CommandSetRules,
		}}
	case store.CommandEnableRules:
		pc.Action = &fleetv1.Command_EnableRules{EnableRules: &fleetv1.EnableRules{
			RuleIds: ruleIDs(cmd.RuleIDs), All: len(cmd.RuleIDs) == 0,
		}}
	}
	return &fleetv1.ControlMessage{Msg: &fleetv1.ControlMessage_Command{Command: pc}}
}

func ruleIDs(ids []int32) []uint32 {
	out := make([]uint32, 0, len(ids))
	for _, id := range ids {
		if id > 0 {
			out = append(out, uint32(id))
		}
	}
	return out
}
