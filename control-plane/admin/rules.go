package admin

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"unicode/utf8"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "github.com/strata/strata/control-plane/gen/strata/admin/v1"
	"github.com/strata/strata/control-plane/store"
)

// RuleStore is the part of store.Store the kill switch uses.
type RuleStore interface {
	SetRuleDisabled(ctx context.Context, group string, rule int32, off bool, reason string, cmds []store.Command, a store.Audit) (store.DisabledRule, []store.Command, error)
	DisabledRules(ctx context.Context, group string) ([]store.DisabledRule, error)
}

// maxRuleID: rule IDs are below 1,000,000 (ir.schema.json ranges).
const maxRuleID = 999_999

func disabledPB(d store.DisabledRule) *adminv1.DisabledRule {
	return &adminv1.DisabledRule{GroupId: d.GroupID, RuleId: uint32(d.RuleID), Reason: d.Reason,
		CreatedBy: d.CreatedBy, CreateTime: timestamppb.New(d.CreatedAt)}
}

// killSwitch checks a request and builds the commands for the group.
func (f *fleetAdmin) killSwitch(ctx context.Context, rule uint32, group, reason, kind string) ([]store.Command, store.Audit, error) {
	if f.rules == nil || f.commands == nil {
		return nil, store.Audit{}, status.Error(codes.FailedPrecondition, "the kill switch is not enabled on this control plane")
	}
	if rule == 0 || rule > maxRuleID {
		return nil, store.Audit{}, status.Error(codes.InvalidArgument, "rule_id must be 1..999999")
	}
	reason = strings.TrimSpace(reason)
	if reason == "" || utf8.RuneCountInString(reason) > 500 || !utf8.ValidString(reason) {
		return nil, store.Audit{}, status.Error(codes.InvalidArgument, "a reason of 1..500 characters is required")
	}
	if group == "" {
		return nil, store.Audit{}, status.Error(codes.InvalidArgument, "group_id is required")
	}
	nodes, resource, err := f.targets(ctx, "", group)
	if err != nil {
		return nil, store.Audit{}, err
	}
	now := f.now()
	cmds := make([]store.Command, 0, len(nodes))
	for _, n := range nodes {
		id, err := newCommandID()
		if err != nil {
			return nil, store.Audit{}, internal("command id", err)
		}
		// a node offline longer gets the list when it connects
		cmds = append(cmds, store.Command{ID: id, NodeID: n, Kind: kind, RuleIDs: []int32{int32(rule)},
			ExpiresAt: now.Add(DiagnosticsTTL).UTC()})
	}
	return cmds, audit(ctx, resource+"/rules/"+strconv.FormatUint(uint64(rule), 10)), nil
}

// EmergencyDisableRule implements POST /v1/rules/{rule_id}:emergencyDisable.
func (f *fleetAdmin) EmergencyDisableRule(ctx context.Context, req *adminv1.EmergencyDisableRuleRequest) (*adminv1.EmergencyDisableRuleResponse, error) {
	cmds, a, err := f.killSwitch(ctx, req.GetRuleId(), req.GetGroupId(), req.GetReason(), store.CommandDisableRules)
	if err != nil {
		return nil, err
	}
	row, out, err := f.rules.SetRuleDisabled(ctx, req.GetGroupId(), int32(req.GetRuleId()), true, strings.TrimSpace(req.GetReason()), cmds, a)
	switch {
	case errors.Is(err, store.ErrTooManyRules):
		return nil, status.Error(codes.ResourceExhausted, err.Error())
	case err != nil:
		return nil, internal("disable rule", err)
	}
	if f.kick != nil {
		f.kick.Kick()
	}
	resp := &adminv1.EmergencyDisableRuleResponse{Rule: disabledPB(row)}
	for _, c := range out {
		resp.Commands = append(resp.Commands, commandPB(c))
	}
	return resp, nil
}

// EnableRule implements POST /v1/rules/{rule_id}:enable.
func (f *fleetAdmin) EnableRule(ctx context.Context, req *adminv1.EnableRuleRequest) (*adminv1.EnableRuleResponse, error) {
	cmds, a, err := f.killSwitch(ctx, req.GetRuleId(), req.GetGroupId(), req.GetReason(), store.CommandEnableRules)
	if err != nil {
		return nil, err
	}
	_, out, err := f.rules.SetRuleDisabled(ctx, req.GetGroupId(), int32(req.GetRuleId()), false, strings.TrimSpace(req.GetReason()), cmds, a)
	if err != nil {
		return nil, internal("enable rule", err)
	}
	if f.kick != nil {
		f.kick.Kick()
	}
	resp := &adminv1.EnableRuleResponse{}
	for _, c := range out {
		resp.Commands = append(resp.Commands, commandPB(c))
	}
	return resp, nil
}

// ListDisabledRules implements GET /v1/rules:disabled.
func (f *fleetAdmin) ListDisabledRules(ctx context.Context, req *adminv1.ListDisabledRulesRequest) (*adminv1.ListDisabledRulesResponse, error) {
	if f.rules == nil {
		return nil, status.Error(codes.FailedPrecondition, "the kill switch is not enabled on this control plane")
	}
	if g := req.GetGroupId(); g != "" && !groupIDRe.MatchString(g) {
		return nil, status.Error(codes.InvalidArgument, "group_id is not valid")
	}
	rows, err := f.rules.DisabledRules(ctx, req.GetGroupId())
	if err != nil {
		return nil, internal("disabled rules", err)
	}
	resp := &adminv1.ListDisabledRulesResponse{}
	for _, r := range rows {
		resp.Rules = append(resp.Rules, disabledPB(r))
	}
	return resp, nil
}
