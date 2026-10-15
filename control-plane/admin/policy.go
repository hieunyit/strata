package admin

import (
	"context"
	"encoding/json"
	"errors"

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
}

// Deployer publishes bundles (policy.Deployer).
type Deployer interface {
	Deploy(ctx context.Context, a store.Audit) (policy.Deployment, error)
}

type policyAdmin struct {
	adminv1.UnimplementedPolicyServiceServer
	store  PolicyStore
	deploy Deployer // nil: deploys are not configured
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
	}
}

func versionPB(v store.PolicyVersion) *adminv1.PolicyVersion {
	return &adminv1.PolicyVersion{PolicyId: v.PolicyID, Version: uint32(v.Version), Spec: specPB(v.Spec), State: v.State,
		CreatedBy: v.CreatedBy, CreateTime: timestamppb.New(v.CreatedAt)}
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
	return &adminv1.CreatePolicyResponse{Policy: policyPB(created)}, nil
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
	return &adminv1.UpdatePolicyResponse{Policy: policyPB(updated)}, nil
}

func (p *policyAdmin) ListPolicyVersions(ctx context.Context, req *adminv1.ListPolicyVersionsRequest) (*adminv1.ListPolicyVersionsResponse, error) {
	vs, err := p.store.ListPolicyVersions(ctx, req.GetPolicyId())
	if err != nil {
		return nil, notFound(err, "policy")
	}
	out := &adminv1.ListPolicyVersionsResponse{}
	for _, v := range vs {
		out.Versions = append(out.Versions, versionPB(v))
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
	if _, err := p.store.GetPolicy(ctx, req.GetPolicyId()); err != nil {
		return nil, notFound(err, "policy")
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
