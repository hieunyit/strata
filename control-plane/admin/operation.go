package admin

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"strconv"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/strata/strata/control-plane/auth"
	adminv1 "github.com/strata/strata/control-plane/gen/strata/admin/v1"
	"github.com/strata/strata/control-plane/replay"
	"github.com/strata/strata/control-plane/store"
)

// OperationStore is the part of store.Store the replay of drafts uses
// (W13-G2-01).
type OperationStore interface {
	CreateReplayOperation(ctx context.Context, policyID string, version int, a store.Audit) (store.Operation, error)
	GetOperation(ctx context.Context, id string) (store.Operation, error)
	LatestReplay(ctx context.Context, policyID string, version int) (store.Operation, error)
}

type operationAdmin struct {
	adminv1.UnimplementedOperationServiceServer
	store OperationStore
}

// GetOperation implements GET /v1/operations/{operation_id}.
func (o *operationAdmin) GetOperation(ctx context.Context, req *adminv1.GetOperationRequest) (*adminv1.GetOperationResponse, error) {
	op, err := o.store.GetOperation(ctx, req.GetOperationId())
	if err != nil {
		return nil, notFound(err, "operation")
	}
	return &adminv1.GetOperationResponse{Operation: operationPB(ctx, op)}, nil
}

// ReplayPolicy implements POST /v1/policies/{policy_id}:replay.
func (p *policyAdmin) ReplayPolicy(ctx context.Context, req *adminv1.ReplayPolicyRequest) (*adminv1.ReplayPolicyResponse, error) {
	if p.ops == nil {
		return nil, status.Error(codes.FailedPrecondition, "replay is not configured on this control plane (strata-replay, object store)")
	}
	version := int(req.GetVersion())
	if version == 0 {
		cur, err := p.store.GetPolicy(ctx, req.GetPolicyId())
		if err != nil {
			return nil, notFound(err, "policy")
		}
		version = cur.CurrentVersion
	}
	op, err := p.ops.CreateReplayOperation(ctx, req.GetPolicyId(), version,
		audit(ctx, "policies/"+req.GetPolicyId()+"/versions/"+strconv.Itoa(version)+":replay"))
	if err != nil {
		return nil, notFound(err, "policy version")
	}
	p.kickReplay()
	return &adminv1.ReplayPolicyResponse{Operation: operationPB(ctx, op)}, nil
}

// GetPolicyVersionReplay implements
// GET /v1/policies/{policy_id}/versions/{version}/replay.
func (p *policyAdmin) GetPolicyVersionReplay(ctx context.Context, req *adminv1.GetPolicyVersionReplayRequest) (*adminv1.GetPolicyVersionReplayResponse, error) {
	if p.ops == nil {
		return nil, status.Error(codes.FailedPrecondition, "replay is not configured on this control plane (strata-replay, object store)")
	}
	op, err := p.ops.LatestReplay(ctx, req.GetPolicyId(), int(req.GetVersion()))
	if errors.Is(err, store.ErrNotFound) {
		return nil, status.Error(codes.NotFound, "no replay of this policy version")
	}
	if err != nil {
		return nil, internal("replay", err)
	}
	return &adminv1.GetPolicyVersionReplayResponse{Operation: operationPB(ctx, op)}, nil
}

// replayNew queues the replay of a version just saved; best effort: the
// edit stands when it cannot be queued (ReplayPolicy queues it again).
func (p *policyAdmin) replayNew(ctx context.Context, policyID string, version int) string {
	if p.ops == nil {
		return ""
	}
	op, err := p.ops.CreateReplayOperation(ctx, policyID, version,
		audit(ctx, "policies/"+policyID+"/versions/"+strconv.Itoa(version)+":replay"))
	if err != nil {
		log.Printf("[WARN] admin: replay of policy %s version %d not queued: %v", policyID, version, err)
		return ""
	}
	p.kickReplay()
	return op.ID
}

func (p *policyAdmin) kickReplay() {
	if p.replayKick != nil {
		p.replayKick()
	}
}

func operationPB(ctx context.Context, o store.Operation) *adminv1.Operation {
	out := &adminv1.Operation{Id: o.ID, Kind: o.Kind, State: o.State, Done: o.Done(), Error: o.Error,
		PolicyId: o.PolicyID, Version: uint32(o.Version), CreatedBy: o.CreatedBy, CreateTime: timestamppb.New(o.CreatedAt)}
	if o.StartedAt != nil {
		out.StartTime = timestamppb.New(*o.StartedAt)
	}
	if o.FinishedAt != nil {
		out.EndTime = timestamppb.New(*o.FinishedAt)
	}
	if o.State == store.OpDone && len(o.Result) > 0 {
		var r replay.Report
		if err := json.Unmarshal(o.Result, &r); err != nil {
			log.Printf("[ERROR] admin: operation %s: result: %v", o.ID, err)
		} else {
			// examples carry (anonymized) request input: only for those who
			// may read input snippets
			p := auth.FromContext(ctx)
			out.Replay = reportPB(r, p != nil && p.Can(auth.PermEventsReadSensitive))
		}
	}
	return out
}

func reportPB(r replay.Report, examples bool) *adminv1.ReplayReport {
	return &adminv1.ReplayReport{Samples: r.Samples(), ElapsedMs: r.ElapsedMs, BaselineBundle: r.BaselineBundle,
		SampleFiles: uint32(r.SampleFiles), SampleBytes: uint64(r.SampleBytes), Truncated: r.Truncated,
		Traffic: comparisonPB(r.Traffic, examples), Corpus: comparisonPB(r.Corpus, examples)}
}

func comparisonPB(x *replay.Route, examples bool) *adminv1.ReplayComparison {
	if x == nil {
		return nil
	}
	out := &adminv1.ReplayComparison{Samples: x.Samples, NewlyBlocked: x.NewlyBlocked, NewlyAllowed: x.NewlyAllowed,
		DraftActions: x.Draft, BaselineActions: x.Baseline, NewlyBlockedPaths: x.NewlyBlockedPaths,
		NewlyBlockedSampled: x.NewlyBlockedSampled, NewlyAllowedSampled: x.NewlyAllowedSampled,
		NewlyBlockedRules: ruleCounts(x.NewlyBlockedRules), NewlyAllowedRules: ruleCounts(x.NewlyAllowedRules)}
	if examples {
		out.ExamplesBlocked, out.ExamplesAllowed = examplesPB(x.ExamplesBlocked), examplesPB(x.ExamplesAllowed)
	}
	return out
}

// ruleCounts: the JSON keys are rule IDs.
func ruleCounts(m map[string]uint64) map[uint32]uint64 {
	out := make(map[uint32]uint64, len(m))
	for k, v := range m {
		if id, err := strconv.ParseUint(k, 10, 32); err == nil {
			out[uint32(id)] = v
		}
	}
	return out
}

func examplesPB(es []replay.Example) []*adminv1.ReplayExample {
	out := make([]*adminv1.ReplayExample, 0, len(es))
	for _, e := range es {
		out = append(out, &adminv1.ReplayExample{TsMs: e.TsMs, NodeId: e.NodeID, Method: e.Method, RawUri: e.RawURI,
			Draft: e.Draft, Baseline: e.Baseline, DraftRules: e.DraftRules, BaselineRules: e.BaselineRules})
	}
	return out
}
