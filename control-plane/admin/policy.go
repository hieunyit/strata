package admin

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"unicode/utf8"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "github.com/strata/strata/control-plane/gen/strata/admin/v1"
	"github.com/strata/strata/control-plane/policy"
	"github.com/strata/strata/control-plane/store"
)

// PolicyStore is the part of store.Store the policy API uses.
type PolicyStore interface {
	CreatePolicy(ctx context.Context, p store.Policy, a store.Audit) (store.Policy, error)
	GetPolicy(ctx context.Context, id string) (store.Policy, error)
	ListPolicies(ctx context.Context) ([]store.Policy, error)
	UpdatePolicy(ctx context.Context, id, etag string, spec json.RawMessage, a store.Audit) (store.Policy, error)
	ListPolicyVersions(ctx context.Context, id string) ([]store.PolicyVersion, error)
	GetPolicyVersion(ctx context.Context, id string, version int) (store.PolicyVersion, error)
	// four eyes (W13-G2-02)
	ListVersionsByState(ctx context.Context, state string) ([]store.PolicyVersion, error)
	SubmitPolicyVersion(ctx context.Context, id string, version int, a store.Audit) (store.PolicyVersion, error)
	DecidePolicyVersion(ctx context.Context, id string, version int, approve bool, comment string, a store.Audit) (store.PolicyVersion, error)
}

// Deployer publishes bundles (policy.Deployer).
type Deployer interface {
	Deploy(ctx context.Context, a store.Audit) (policy.Deployment, error)
}

type policyAdmin struct {
	adminv1.UnimplementedPolicyServiceServer
	store  PolicyStore
	deploy Deployer // nil: deploys are not configured
	// ops queues the replay of each new version (W13-G2-01); nil: replay
	// is not configured. replayKick wakes the runner.
	ops        OperationStore
	replayKick func()
}

var (
	modeToPB = map[string]adminv1.PolicySpec_Mode{"shadow": adminv1.PolicySpec_MODE_SHADOW, "enforce": adminv1.PolicySpec_MODE_ENFORCE}
	modeOfPB = map[adminv1.PolicySpec_Mode]string{adminv1.PolicySpec_MODE_SHADOW: "shadow", adminv1.PolicySpec_MODE_ENFORCE: "enforce"}
	overToPB = map[string]adminv1.PolicySpec_Oversize{"": adminv1.PolicySpec_OVERSIZE_UNSPECIFIED, "pass": adminv1.PolicySpec_OVERSIZE_PASS, "block": adminv1.PolicySpec_OVERSIZE_BLOCK}
	overOfPB = map[adminv1.PolicySpec_Oversize]string{adminv1.PolicySpec_OVERSIZE_UNSPECIFIED: "", adminv1.PolicySpec_OVERSIZE_PASS: "pass", adminv1.PolicySpec_OVERSIZE_BLOCK: "block"}
)

// specOf converts and validates a spec from the API.
func specOf(pb *adminv1.PolicySpec) (json.RawMessage, error) {
	if pb == nil {
		return nil, status.Error(codes.InvalidArgument, "policy.spec is required")
	}
	s := policy.Spec{Mode: modeOfPB[pb.GetMode()], Oversize: overOfPB[pb.GetOversize()], MaxSnippetSize: int(pb.GetMaxSnippetSize()),
		CanaryPercent: pb.GetCanaryPercent(), MaxArgs: int(pb.GetMaxArgs())}
	if s.MaxSnippetSize == 128 {
		s.MaxSnippetSize = 0 // the default, stored as absent
	}
	if pv := pb.GetPrivacy(); pv != nil && (len(pv.GetSensitiveFields()) > 0 || len(pv.GetMaskPatterns()) > 0 || pv.GetIdentity() == "hmac") {
		s.Privacy = &policy.Privacy{SensitiveFields: pv.GetSensitiveFields(), MaskPatterns: pv.GetMaskPatterns(), Identity: pv.GetIdentity()}
	}
	if r := pb.GetResponse(); r != nil && (r.GetAllowedCodesCheck() || r.GetDbErrors() || len(r.GetDataGuard()) > 0) {
		s.Response = &policy.Response{AllowedCodesCheck: r.GetAllowedCodesCheck(), DBErrors: r.GetDbErrors(), DataGuard: r.GetDataGuard()}
	}
	if err := s.Validate(); err != nil {
		return nil, status.Error(codes.InvalidArgument, "policy.spec: "+err.Error())
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return nil, status.Error(codes.Internal, "spec")
	}
	return raw, nil
}

func specPB(raw json.RawMessage) *adminv1.PolicySpec {
	var s policy.Spec
	_ = json.Unmarshal(raw, &s)
	out := &adminv1.PolicySpec{Mode: modeToPB[s.Mode], Oversize: overToPB[s.Oversize], MaxSnippetSize: uint32(s.MaxSnippetSize),
		CanaryPercent: s.CanaryPercent, MaxArgs: uint32(s.MaxArgs)}
	if s.Privacy != nil {
		out.Privacy = &adminv1.PrivacySettings{SensitiveFields: s.Privacy.SensitiveFields, MaskPatterns: s.Privacy.MaskPatterns, Identity: s.Privacy.Identity}
	}
	if s.Response != nil {
		out.Response = &adminv1.ResponseLayer{AllowedCodesCheck: s.Response.AllowedCodesCheck, DbErrors: s.Response.DBErrors, DataGuard: s.Response.DataGuard}
	}
	return out
}

func policyPB(p store.Policy) *adminv1.Policy {
	return &adminv1.Policy{
		Id: p.ID, Name: p.Name, Spec: specPB(p.Spec), Version: uint32(p.CurrentVersion), Etag: p.Etag,
		CreatedBy: p.CreatedBy, CreateTime: timestamppb.New(p.CreatedAt), UpdateTime: timestamppb.New(p.UpdatedAt),
		ApprovedVersion: uint32(p.ApprovedVersion), DeployedVersion: uint32(p.DeployedVersion),
	}
}

func versionPB(v store.PolicyVersion) *adminv1.PolicyVersion {
	out := &adminv1.PolicyVersion{PolicyId: v.PolicyID, Version: uint32(v.Version), Spec: specPB(v.Spec), State: v.State,
		CreatedBy: v.CreatedBy, CreateTime: timestamppb.New(v.CreatedAt), SubmittedBy: v.SubmittedBy,
		DecidedBy: v.DecidedBy, DecisionComment: v.DecisionComment}
	if v.SubmittedAt != nil {
		out.SubmitTime = timestamppb.New(*v.SubmittedAt)
	}
	if v.DecidedAt != nil {
		out.DecideTime = timestamppb.New(*v.DecidedAt)
	}
	return out
}

func notFound(err error, what string) error {
	if errors.Is(err, store.ErrNotFound) {
		return status.Error(codes.NotFound, "no such "+what)
	}
	return internal(what, err)
}

func (p *policyAdmin) ListPolicies(ctx context.Context, _ *adminv1.ListPoliciesRequest) (*adminv1.ListPoliciesResponse, error) {
	ps, err := p.store.ListPolicies(ctx)
	if err != nil {
		return nil, internal("list policies", err)
	}
	out := &adminv1.ListPoliciesResponse{}
	for _, x := range ps {
		out.Policies = append(out.Policies, policyPB(x))
	}
	return out, nil
}

func (p *policyAdmin) GetPolicy(ctx context.Context, req *adminv1.GetPolicyRequest) (*adminv1.GetPolicyResponse, error) {
	x, err := p.store.GetPolicy(ctx, req.GetPolicyId())
	if err != nil {
		return nil, notFound(err, "policy")
	}
	return &adminv1.GetPolicyResponse{Policy: policyPB(x)}, nil
}

func (p *policyAdmin) CreatePolicy(ctx context.Context, req *adminv1.CreatePolicyRequest) (*adminv1.CreatePolicyResponse, error) {
	in := req.GetPolicy()
	if !policy.IDPattern.MatchString(in.GetId()) {
		return nil, status.Error(codes.InvalidArgument, "policy.id must match [a-z0-9][a-z0-9-]{0,62}")
	}
	if !policy.NamePattern.MatchString(in.GetName()) {
		return nil, status.Error(codes.InvalidArgument, "policy.name must match [a-z0-9._-]{1,55}")
	}
	spec, err := specOf(in.GetSpec())
	if err != nil {
		return nil, err
	}
	created, err := p.store.CreatePolicy(ctx, store.Policy{ID: in.GetId(), Name: in.GetName(), Spec: spec}, audit(ctx, "policies/"+in.GetId()))
	switch {
	case errors.Is(err, store.ErrExists):
		return nil, status.Error(codes.AlreadyExists, "a policy with this id or name exists")
	case err != nil:
		return nil, internal("create policy", err)
	}
	return &adminv1.CreatePolicyResponse{Policy: policyPB(created), ReplayOperation: p.replayNew(ctx, created.ID, created.CurrentVersion)}, nil
}

func (p *policyAdmin) UpdatePolicy(ctx context.Context, req *adminv1.UpdatePolicyRequest) (*adminv1.UpdatePolicyResponse, error) {
	in := req.GetPolicy()
	if in.GetEtag() == "" {
		return nil, status.Error(codes.InvalidArgument, "policy.etag is required: send the etag the edit is based on")
	}
	if in.GetName() != "" {
		cur, err := p.store.GetPolicy(ctx, in.GetId())
		if err != nil {
			return nil, notFound(err, "policy")
		}
		if cur.Name != in.GetName() {
			return nil, status.Error(codes.InvalidArgument, "policy.name cannot change")
		}
	}
	spec, err := specOf(in.GetSpec())
	if err != nil {
		return nil, err
	}
	updated, err := p.store.UpdatePolicy(ctx, in.GetId(), in.GetEtag(), spec, audit(ctx, "policies/"+in.GetId()))
	switch {
	case errors.Is(err, store.ErrEtagMismatch):
		// grpc-gateway answers ABORTED with 409 Conflict.
		return nil, status.Error(codes.Aborted, "the policy changed since it was read (etag mismatch); reload and edit again")
	case err != nil:
		return nil, notFound(err, "policy")
	}
	return &adminv1.UpdatePolicyResponse{Policy: policyPB(updated), ReplayOperation: p.replayNew(ctx, updated.ID, updated.CurrentVersion)}, nil
}

var versionStates = map[string]bool{store.VersionDraft: true, store.VersionSubmitted: true, store.VersionApproved: true,
	store.VersionRejected: true, store.VersionDeployed: true}

func (p *policyAdmin) ListPolicyVersions(ctx context.Context, req *adminv1.ListPolicyVersionsRequest) (*adminv1.ListPolicyVersionsResponse, error) {
	state := req.GetState()
	if state != "" && !versionStates[state] {
		return nil, status.Error(codes.InvalidArgument, "state must be DRAFT, SUBMITTED, APPROVED, REJECTED or DEPLOYED")
	}
	var vs []store.PolicyVersion
	var err error
	if req.GetPolicyId() == "-" {
		if state == "" {
			return nil, status.Error(codes.InvalidArgument, "policy_id - (every policy) needs a state")
		}
		if vs, err = p.store.ListVersionsByState(ctx, state); err != nil {
			return nil, internal("list versions", err)
		}
	} else if vs, err = p.store.ListPolicyVersions(ctx, req.GetPolicyId()); err != nil {
		return nil, notFound(err, "policy")
	}
	out := &adminv1.ListPolicyVersionsResponse{}
	for _, v := range vs {
		if state == "" || v.State == state {
			out.Versions = append(out.Versions, versionPB(v))
		}
	}
	return out, nil
}

func (p *policyAdmin) GetPolicyVersion(ctx context.Context, req *adminv1.GetPolicyVersionRequest) (*adminv1.GetPolicyVersionResponse, error) {
	v, err := p.store.GetPolicyVersion(ctx, req.GetPolicyId(), int(req.GetVersion()))
	if err != nil {
		return nil, notFound(err, "policy version")
	}
	return &adminv1.GetPolicyVersionResponse{Version: versionPB(v)}, nil
}

func (p *policyAdmin) DeployPolicy(ctx context.Context, req *adminv1.DeployPolicyRequest) (*adminv1.DeployPolicyResponse, error) {
	if p.deploy == nil {
		return nil, status.Error(codes.FailedPrecondition, "deploys are not configured on this control plane (compiler, signing key, object store)")
	}
	cur, err := p.store.GetPolicy(ctx, req.GetPolicyId())
	if err != nil {
		return nil, notFound(err, "policy")
	}
	// four eyes (W13-G2-02): the policy's newest version must be approved
	if cur.ApprovedVersion != cur.CurrentVersion {
		v, err := p.store.GetPolicyVersion(ctx, cur.ID, cur.CurrentVersion)
		if err != nil {
			return nil, notFound(err, "policy version")
		}
		return nil, status.Errorf(codes.FailedPrecondition,
			"version %d of policy %s is %s: it must be submitted and approved by someone else before a deploy (four eyes)",
			cur.CurrentVersion, cur.ID, v.State)
	}
	d, err := p.deploy.Deploy(ctx, audit(ctx, "policies/"+req.GetPolicyId()+":deploy"))
	var costErr *policy.CostError
	switch {
	case errors.As(err, &costErr):
		return nil, status.Error(codes.InvalidArgument, costErr.Error())
	case err != nil:
		return nil, internal("deploy", err)
	}
	out := &adminv1.DeployPolicyResponse{Bundle: bundlePB(d.Bundle)}
	if d.Rollout != nil {
		out.RolloutId = d.Rollout.ID
	}
	return out, nil
}

// SubmitPolicy implements POST /v1/policies/{policy_id}:submit.
func (p *policyAdmin) SubmitPolicy(ctx context.Context, req *adminv1.SubmitPolicyRequest) (*adminv1.SubmitPolicyResponse, error) {
	version := int(req.GetVersion())
	if version == 0 {
		cur, err := p.store.GetPolicy(ctx, req.GetPolicyId())
		if err != nil {
			return nil, notFound(err, "policy")
		}
		version = cur.CurrentVersion
	}
	v, err := p.store.SubmitPolicyVersion(ctx, req.GetPolicyId(), version,
		audit(ctx, "policies/"+req.GetPolicyId()+"/versions/"+strconv.Itoa(version)+":submit"))
	if err != nil {
		return nil, decisionErr(err)
	}
	return &adminv1.SubmitPolicyResponse{Version: versionPB(v)}, nil
}

// ApprovePolicy implements POST /v1/policies/{policy_id}:approve.
func (p *policyAdmin) ApprovePolicy(ctx context.Context, req *adminv1.ApprovePolicyRequest) (*adminv1.ApprovePolicyResponse, error) {
	v, err := p.decide(ctx, req.GetPolicyId(), req.GetVersion(), true, req.GetComment())
	if err != nil {
		return nil, err
	}
	return &adminv1.ApprovePolicyResponse{Version: versionPB(v)}, nil
}

// RejectPolicy implements POST /v1/policies/{policy_id}:reject.
func (p *policyAdmin) RejectPolicy(ctx context.Context, req *adminv1.RejectPolicyRequest) (*adminv1.RejectPolicyResponse, error) {
	if strings.TrimSpace(req.GetComment()) == "" {
		return nil, status.Error(codes.InvalidArgument, "a comment saying why is required")
	}
	v, err := p.decide(ctx, req.GetPolicyId(), req.GetVersion(), false, req.GetComment())
	if err != nil {
		return nil, err
	}
	return &adminv1.RejectPolicyResponse{Version: versionPB(v)}, nil
}

func (p *policyAdmin) decide(ctx context.Context, id string, version uint32, approve bool, comment string) (store.PolicyVersion, error) {
	if version == 0 {
		return store.PolicyVersion{}, status.Error(codes.InvalidArgument, "version is required: the one reviewed")
	}
	if utf8.RuneCountInString(comment) > 1000 {
		return store.PolicyVersion{}, status.Error(codes.InvalidArgument, "comment: at most 1000 characters")
	}
	verb := ":reject"
	if approve {
		verb = ":approve"
		if err := p.replayDone(ctx, id, int(version)); err != nil {
			return store.PolicyVersion{}, err
		}
	}
	v, err := p.store.DecidePolicyVersion(ctx, id, int(version), approve, comment,
		audit(ctx, "policies/"+id+"/versions/"+strconv.Itoa(int(version))+verb))
	if err != nil {
		return store.PolicyVersion{}, decisionErr(err)
	}
	return v, nil
}

func decisionErr(err error) error {
	var se *store.StateError
	switch {
	case errors.Is(err, store.ErrFourEyes):
		return status.Error(codes.PermissionDenied, "whoever drafted or submitted a version cannot approve it (four eyes)")
	case errors.As(err, &se):
		return status.Error(codes.FailedPrecondition, se.Msg)
	}
	return notFound(err, "policy version")
}

// replayDone: with replay configured, a version is approved only once its
// newest replay is DONE (PO 16/10/2026: nothing reaches production
// without a replay).
func (p *policyAdmin) replayDone(ctx context.Context, id string, version int) error {
	if p.ops == nil {
		return nil
	}
	op, err := p.ops.LatestReplay(ctx, id, version)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return status.Errorf(codes.FailedPrecondition,
			"version %d has no replay: run POST /v1/policies/%s:replay, then approve once it is DONE", version, id)
	case err != nil:
		return internal("replay", err)
	case op.State == store.OpFailed:
		return status.Errorf(codes.FailedPrecondition,
			"the replay of version %d failed (%s): run POST /v1/policies/%s:replay again", version, op.Error, id)
	case op.State != store.OpDone:
		return status.Errorf(codes.FailedPrecondition,
			"the replay of version %d is %s: approve once it is DONE (GET /v1/operations/%s)", version, op.State, op.ID)
	}
	return nil
}
