package admin

import (
	"context"
	"errors"
	"math"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "github.com/strata/strata/control-plane/gen/strata/admin/v1"
	"github.com/strata/strata/control-plane/store"
)

// ReplayStore is the part of store.Store replay sampling uses (W12-N-01).
type ReplayStore interface {
	SetReplaySampling(ctx context.Context, group string, rateBp int, rotate bool, cmds []store.Command, a store.Audit) (store.ReplaySampling, []store.Command, error)
	GetReplaySampling(ctx context.Context, group string) (store.ReplaySampling, error)
}

func replayPB(r store.ReplaySampling) *adminv1.ReplaySampling {
	return &adminv1.ReplaySampling{GroupId: r.GroupID, RatePercent: float64(r.RateBp) / 100, KeyId: r.KeyID,
		UpdatedBy: r.UpdatedBy, UpdateTime: timestamppb.New(r.UpdatedAt)}
}

// SetReplaySampling implements POST /v1/groups/{group_id}:setReplaySampling.
func (f *fleetAdmin) SetReplaySampling(ctx context.Context, req *adminv1.SetReplaySamplingRequest) (*adminv1.SetReplaySamplingResponse, error) {
	if f.replay == nil || f.commands == nil {
		return nil, status.Error(codes.FailedPrecondition, "replay sampling is not enabled on this control plane")
	}
	p := req.GetRatePercent()
	bp := math.Round(p * 100)
	if math.IsNaN(p) || p < 0 || p > 100 || math.Abs(p*100-bp) > 1e-6 {
		return nil, status.Error(codes.InvalidArgument, "rate_percent must be 0 to 100 with at most two decimals")
	}
	if bp > 0 && !f.replayApproved {
		return nil, status.Error(codes.FailedPrecondition,
			"sampling real traffic waits for the legal review of docs/spec/replay-sample.md (start the control plane with -replay-sampling-approved)")
	}
	group := req.GetGroupId()
	if group == "" {
		return nil, status.Error(codes.InvalidArgument, "group_id is required")
	}
	nodes, resource, err := f.targets(ctx, "", group)
	if err != nil && status.Code(err) != codes.NotFound {
		return nil, err
	}
	now := f.now()
	cmds := make([]store.Command, 0, len(nodes))
	for _, n := range nodes {
		id, err := newCommandID()
		if err != nil {
			return nil, internal("command id", err)
		}
		cmds = append(cmds, store.Command{ID: id, NodeID: n, Kind: store.CommandReplaySync, ExpiresAt: now.Add(DiagnosticsTTL).UTC()})
	}
	if resource == "" {
		resource = "groups/" + group
	}
	row, out, err := f.replay.SetReplaySampling(ctx, group, int(bp), req.GetRotateKey(), cmds, audit(ctx, resource+":setReplaySampling"))
	if err != nil {
		return nil, internal("replay sampling", err)
	}
	if f.kick != nil {
		f.kick.Kick()
	}
	resp := &adminv1.SetReplaySamplingResponse{Sampling: replayPB(row)}
	for _, c := range out {
		resp.Commands = append(resp.Commands, commandPB(c))
	}
	return resp, nil
}

// GetReplaySampling implements GET /v1/groups/{group_id}/replaySampling.
func (f *fleetAdmin) GetReplaySampling(ctx context.Context, req *adminv1.GetReplaySamplingRequest) (*adminv1.GetReplaySamplingResponse, error) {
	if f.replay == nil {
		return nil, status.Error(codes.FailedPrecondition, "replay sampling is not enabled on this control plane")
	}
	if !groupIDRe.MatchString(req.GetGroupId()) {
		return nil, status.Error(codes.InvalidArgument, "group_id is not valid")
	}
	r, err := f.replay.GetReplaySampling(ctx, req.GetGroupId())
	switch {
	case errors.Is(err, store.ErrNotFound):
		return &adminv1.GetReplaySamplingResponse{Sampling: &adminv1.ReplaySampling{GroupId: req.GetGroupId()}}, nil
	case err != nil:
		return nil, internal("replay sampling", err)
	}
	return &adminv1.GetReplaySamplingResponse{Sampling: replayPB(r)}, nil
}
