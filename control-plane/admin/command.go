package admin

import (
	"context"
	"crypto/rand"
	"errors"
	"regexp"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "github.com/strata/strata/control-plane/gen/strata/admin/v1"
	"github.com/strata/strata/control-plane/store"
)

// CommandStore is the part of store.Store the command API uses.
type CommandStore interface {
	CreateCommands(ctx context.Context, cmds []store.Command, a store.Audit) ([]store.Command, error)
	GroupNodes(ctx context.Context, group string) ([]string, error)
	GetCommand(ctx context.Context, id string) (store.Command, error)
	ListCommands(ctx context.Context, node string, limit int) ([]store.Command, error)
}

// Command limits.
const (
	MaxForceShadow  = 24 * time.Hour
	DiagnosticsTTL  = 10 * time.Minute
	maxNodesCommand = 10000
)

var (
	policyIDRe  = regexp.MustCompile(`^[a-z0-9._-]{1,55}$`)
	commandIDRe = regexp.MustCompile(`^cmd-[a-z2-7]{16}$`)
)

func commandPB(c store.Command) *adminv1.NodeCommand {
	return &adminv1.NodeCommand{Id: c.ID, NodeId: c.NodeID, Kind: c.Kind, PolicyId: c.PolicyID,
		DurationSeconds: uint32(c.DurationSeconds), State: c.State, Error: c.Error, Output: c.Output,
		CreatedBy: c.CreatedBy, CreateTime: timestamppb.New(c.CreatedAt), ExpireTime: timestamppb.New(c.ExpiresAt),
		UpdateTime: timestamppb.New(c.UpdatedAt)}
}

func newCommandID() (string, error) {
	b := make([]byte, 10)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "cmd-" + strings.ToLower(tokenEncoding.EncodeToString(b)), nil
}

func (f *fleetAdmin) create(ctx context.Context, kind, policy string, dur time.Duration, nodes []string, resource string) ([]store.Command, error) {
	if f.commands == nil {
		return nil, status.Error(codes.FailedPrecondition, "commands are not enabled on this control plane")
	}
	now := f.now()
	ttl := dur
	if kind == store.CommandDiagnostics {
		ttl = DiagnosticsTTL
	}
	cmds := make([]store.Command, 0, len(nodes))
	for _, n := range nodes {
		id, err := newCommandID()
		if err != nil {
			return nil, internal("command id", err)
		}
		cmds = append(cmds, store.Command{ID: id, NodeID: n, Kind: kind, PolicyID: policy,
			DurationSeconds: int(dur / time.Second), ExpiresAt: now.Add(ttl).UTC()})
	}
	out, err := f.commands.CreateCommands(ctx, cmds, audit(ctx, resource))
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil, status.Error(codes.NotFound, "no such node, or the node is revoked")
	case err != nil:
		return nil, internal("create command", err)
	}
	if f.kick != nil {
		f.kick.Kick()
	}
	return out, nil
}

func (f *fleetAdmin) ForceShadow(ctx context.Context, req *adminv1.ForceShadowRequest) (*adminv1.ForceShadowResponse, error) {
	if (req.GetNodeId() == "") == (req.GetGroupId() == "") {
		return nil, status.Error(codes.InvalidArgument, "exactly one of node_id and group_id is required")
	}
	if p := req.GetPolicyId(); p != "" && !policyIDRe.MatchString(p) {
		return nil, status.Error(codes.InvalidArgument, "policy_id must match [a-z0-9._-]{1,55}")
	}
	dur := time.Duration(req.GetDurationSeconds()) * time.Second
	if dur < time.Second || dur > MaxForceShadow {
		return nil, status.Error(codes.InvalidArgument, "duration_seconds must be between 1 and 86400")
	}
	var nodes []string
	resource := "nodes/" + req.GetNodeId()
	if id := req.GetNodeId(); id != "" {
		if len(id) > 128 {
			return nil, status.Error(codes.InvalidArgument, "node_id is not valid")
		}
		nodes = []string{id}
	} else {
		if !groupIDRe.MatchString(req.GetGroupId()) {
			return nil, status.Error(codes.InvalidArgument, "group_id is not valid")
		}
		resource = "groups/" + req.GetGroupId()
		if f.commands == nil {
			return nil, status.Error(codes.FailedPrecondition, "commands are not enabled on this control plane")
		}
		var err error
		if nodes, err = f.commands.GroupNodes(ctx, req.GetGroupId()); err != nil {
			return nil, internal("group nodes", err)
		}
		if len(nodes) == 0 {
			return nil, status.Error(codes.NotFound, "the group has no active node")
		}
		if len(nodes) > maxNodesCommand {
			return nil, status.Error(codes.InvalidArgument, "too many nodes in the group")
		}
	}
	cmds, err := f.create(ctx, store.CommandForceShadow, req.GetPolicyId(), dur, nodes, resource+":forceShadow")
	if err != nil {
		return nil, err
	}
	out := &adminv1.ForceShadowResponse{}
	for _, c := range cmds {
		out.Commands = append(out.Commands, commandPB(c))
	}
	return out, nil
}

func (f *fleetAdmin) CollectDiagnostics(ctx context.Context, req *adminv1.CollectDiagnosticsRequest) (*adminv1.CollectDiagnosticsResponse, error) {
	id := req.GetNodeId()
	if id == "" || len(id) > 128 {
		return nil, status.Error(codes.InvalidArgument, "node_id is required")
	}
	cmds, err := f.create(ctx, store.CommandDiagnostics, "", 0, []string{id}, "nodes/"+id+":collectDiagnostics")
	if err != nil {
		return nil, err
	}
	return &adminv1.CollectDiagnosticsResponse{Command: commandPB(cmds[0])}, nil
}

func (f *fleetAdmin) ListCommands(ctx context.Context, req *adminv1.ListCommandsRequest) (*adminv1.ListCommandsResponse, error) {
	if f.commands == nil {
		return nil, status.Error(codes.FailedPrecondition, "commands are not enabled on this control plane")
	}
	if len(req.GetNodeId()) > 128 {
		return nil, status.Error(codes.InvalidArgument, "node_id is not valid")
	}
	cs, err := f.commands.ListCommands(ctx, req.GetNodeId(), 100)
	if err != nil {
		return nil, internal("list commands", err)
	}
	out := &adminv1.ListCommandsResponse{}
	for _, c := range cs {
		out.Commands = append(out.Commands, commandPB(c))
	}
	return out, nil
}

func (f *fleetAdmin) GetCommand(ctx context.Context, req *adminv1.GetCommandRequest) (*adminv1.GetCommandResponse, error) {
	if f.commands == nil {
		return nil, status.Error(codes.FailedPrecondition, "commands are not enabled on this control plane")
	}
	if !commandIDRe.MatchString(req.GetCommandId()) {
		return nil, status.Error(codes.InvalidArgument, "command_id is not valid")
	}
	c, err := f.commands.GetCommand(ctx, req.GetCommandId())
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil, status.Error(codes.NotFound, "no such command")
	case err != nil:
		return nil, internal("get command", err)
	}
	return &adminv1.GetCommandResponse{Command: commandPB(c)}, nil
}
