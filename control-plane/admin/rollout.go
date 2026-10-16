package admin

import (
	"context"
	"encoding/hex"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "github.com/strata/strata/control-plane/gen/strata/admin/v1"
	"github.com/strata/strata/control-plane/store"
)

// RolloutStore is the part of store.Store the rollout API uses.
type RolloutStore interface {
	ListBundles(ctx context.Context, limit int) ([]store.Bundle, error)
	ListRollouts(ctx context.Context, limit int) ([]store.Rollout, error)
	GetRollout(ctx context.Context, id int64) (store.Rollout, error)
	SetRolloutState(ctx context.Context, id int64, to, reason string, from []string, a store.Audit) (store.Rollout, error)
}

// Kicker wakes the rollout controller (fleet.Rollouts).
type Kicker interface{ Kick() }

type rolloutAdmin struct {
	adminv1.UnimplementedRolloutServiceServer
	store RolloutStore
	kick  Kicker
}

func bundlePB(b store.Bundle) *adminv1.Bundle {
	contents := map[string]uint32{}
	for k, v := range b.Contents {
		contents[k] = uint32(v)
	}
	return &adminv1.Bundle{InputDigest: b.InputDigest, Version: b.Version, Sha256: hex.EncodeToString(b.SHA256), ObjectKey: b.ObjectKey,
		SizeBytes: uint64(b.SizeBytes), Contents: contents, CreatedBy: b.CreatedBy, CreateTime: timestamppb.New(b.CreatedAt)}
}

func rolloutPB(r store.Rollout) *adminv1.Rollout {
	out := &adminv1.Rollout{Id: r.ID, BundleVersion: r.BundleVersion, State: r.State, CurrentWave: int32(r.CurrentWave),
		SoakSeconds: int32(r.SoakSeconds), Reason: r.Reason, CreatedBy: r.CreatedBy,
		CreateTime: timestamppb.New(r.CreatedAt), UpdateTime: timestamppb.New(r.UpdatedAt)}
	for _, w := range r.Waves {
		out.Waves = append(out.Waves, int32(w))
	}
	for _, n := range r.Nodes {
		out.Nodes = append(out.Nodes, &adminv1.RolloutNode{NodeId: n.NodeID, Wave: int32(n.Wave), State: n.State,
			Error: n.Error, UpdateTime: timestamppb.New(n.UpdatedAt)})
	}
	return out
}

func (r *rolloutAdmin) ListBundles(ctx context.Context, _ *adminv1.ListBundlesRequest) (*adminv1.ListBundlesResponse, error) {
	bs, err := r.store.ListBundles(ctx, 100)
	if err != nil {
		return nil, internal("list bundles", err)
	}
	out := &adminv1.ListBundlesResponse{}
	for _, b := range bs {
		out.Bundles = append(out.Bundles, bundlePB(b))
	}
	return out, nil
}

func (r *rolloutAdmin) ListRollouts(ctx context.Context, _ *adminv1.ListRolloutsRequest) (*adminv1.ListRolloutsResponse, error) {
	rs, err := r.store.ListRollouts(ctx, 50)
	if err != nil {
		return nil, internal("list rollouts", err)
	}
	out := &adminv1.ListRolloutsResponse{}
	for _, x := range rs {
		out.Rollouts = append(out.Rollouts, rolloutPB(x))
	}
	return out, nil
}

func (r *rolloutAdmin) GetRollout(ctx context.Context, req *adminv1.GetRolloutRequest) (*adminv1.GetRolloutResponse, error) {
	x, err := r.store.GetRollout(ctx, req.GetRolloutId())
	if err != nil {
		return nil, notFound(err, "rollout")
	}
	return &adminv1.GetRolloutResponse{Rollout: rolloutPB(x)}, nil
}

func (r *rolloutAdmin) set(ctx context.Context, id int64, to string, from []string, reason string) (*adminv1.Rollout, error) {
	x, err := r.store.SetRolloutState(ctx, id, to, reason, from, audit(ctx, ""))
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil, status.Error(codes.NotFound, "no such rollout")
	case errors.Is(err, store.ErrRolloutState):
		return nil, status.Errorf(codes.FailedPrecondition, "the rollout cannot go to %s from its state", to)
	case err != nil:
		return nil, internal("rollout", err)
	}
	if r.kick != nil {
		r.kick.Kick()
	}
	return rolloutPB(x), nil
}

func (r *rolloutAdmin) PauseRollout(ctx context.Context, req *adminv1.PauseRolloutRequest) (*adminv1.PauseRolloutResponse, error) {
	x, err := r.set(ctx, req.GetRolloutId(), store.RolloutPaused, []string{store.RolloutRunning}, "paused by "+audit(ctx, "").Actor)
	if err != nil {
		return nil, err
	}
	return &adminv1.PauseRolloutResponse{Rollout: x}, nil
}

func (r *rolloutAdmin) ResumeRollout(ctx context.Context, req *adminv1.ResumeRolloutRequest) (*adminv1.ResumeRolloutResponse, error) {
	x, err := r.set(ctx, req.GetRolloutId(), store.RolloutRunning, []string{store.RolloutPaused, store.RolloutFailed}, "")
	if err != nil {
		return nil, err
	}
	return &adminv1.ResumeRolloutResponse{Rollout: x}, nil
}

func (r *rolloutAdmin) AbortRollout(ctx context.Context, req *adminv1.AbortRolloutRequest) (*adminv1.AbortRolloutResponse, error) {
	x, err := r.set(ctx, req.GetRolloutId(), store.RolloutAborted,
		[]string{store.RolloutRunning, store.RolloutPaused, store.RolloutFailed}, "aborted by "+audit(ctx, "").Actor)
	if err != nil {
		return nil, err
	}
	return &adminv1.AbortRolloutResponse{Rollout: x}, nil
}
