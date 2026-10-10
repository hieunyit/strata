package admin

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"log"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/strata/strata/control-plane/auth"
	adminv1 "github.com/strata/strata/control-plane/gen/strata/admin/v1"
	"github.com/strata/strata/control-plane/store"
)

// FleetStore is the part of store.Store the fleet admin API uses.
type FleetStore interface {
	CreateGroup(ctx context.Context, g store.Group, a store.Audit) (store.Group, error)
	ListGroups(ctx context.Context) ([]store.Group, error)
	CreateEnrollmentToken(ctx context.Context, id, groupID, token string, expires time.Time, a store.Audit) error
	ListNodes(ctx context.Context) ([]store.Node, error)
	RevokeNode(ctx context.Context, id string, at time.Time, a store.Audit) (store.Node, error)
}

// NodePresence is the fleet stream registry (fleet.Presence).
type NodePresence interface {
	Online(node string, connected bool, lastSeen *time.Time, revoked bool, now time.Time) bool
	Cut(node string)
}

// MaxTokenTTL of an enrollment token (nginx-module.md › Đăng ký node).
const MaxTokenTTL = 24 * time.Hour

var groupIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

type fleetAdmin struct {
	adminv1.UnimplementedFleetAdminServiceServer
	store    FleetStore
	presence NodePresence
	now      func() time.Time
}

// audit describes the caller of a write for the audit log.
func audit(ctx context.Context, resource string) store.Audit {
	a := store.Audit{Resource: resource, Channel: "api"}
	if p := auth.FromContext(ctx); p != nil {
		a.Actor = p.Subject
		if p.Name != "" {
			a.Actor = p.Name + " (" + p.Subject + ")"
		}
	}
	if m, ok := grpc.Method(ctx); ok {
		a.Action = m
	}
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		// The UI marks its calls (Grpc-Metadata-Strata-Channel: ui); the
		// value only labels the entry, it grants nothing.
		if v := md.Get("strata-channel"); len(v) > 0 && (v[0] == "ui" || v[0] == "gitops") {
			a.Channel = v[0]
		}
		if v := md.Get("x-request-id"); len(v) > 0 && len(v[0]) <= 128 {
			a.RequestID = v[0]
		}
	}
	return a
}

func internal(what string, err error) error {
	log.Printf("[ERROR] admin: %s: %v", what, err)
	return status.Error(codes.Internal, what+" failed")
}

func groupPB(g store.Group) *adminv1.Group {
	return &adminv1.Group{Id: g.ID, Name: g.Name, CreateTime: timestamppb.New(g.CreatedAt)}
}

func (f *fleetAdmin) ListGroups(ctx context.Context, _ *adminv1.ListGroupsRequest) (*adminv1.ListGroupsResponse, error) {
	gs, err := f.store.ListGroups(ctx)
	if err != nil {
		return nil, internal("list groups", err)
	}
	out := &adminv1.ListGroupsResponse{}
	for _, g := range gs {
		out.Groups = append(out.Groups, groupPB(g))
	}
	return out, nil
}

func (f *fleetAdmin) CreateGroup(ctx context.Context, req *adminv1.CreateGroupRequest) (*adminv1.CreateGroupResponse, error) {
	g := req.GetGroup()
	name := strings.TrimSpace(g.GetName())
	if !groupIDRe.MatchString(g.GetId()) {
		return nil, status.Error(codes.InvalidArgument, "group.id must match [a-z0-9][a-z0-9-]{0,62}")
	}
	if name == "" || utf8.RuneCountInString(name) > 128 {
		return nil, status.Error(codes.InvalidArgument, "group.name must have 1 to 128 characters")
	}
	created, err := f.store.CreateGroup(ctx, store.Group{ID: g.GetId(), Name: name}, audit(ctx, "groups/"+g.GetId()))
	switch {
	case errors.Is(err, store.ErrExists):
		return nil, status.Error(codes.AlreadyExists, "a group with this id or name exists")
	case err != nil:
		return nil, internal("create group", err)
	}
	return &adminv1.CreateGroupResponse{Group: groupPB(created)}, nil
}

var tokenEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

func (f *fleetAdmin) CreateEnrollmentToken(ctx context.Context, req *adminv1.CreateEnrollmentTokenRequest) (*adminv1.CreateEnrollmentTokenResponse, error) {
	if !groupIDRe.MatchString(req.GetGroupId()) {
		return nil, status.Error(codes.InvalidArgument, "group_id is not valid")
	}
	ttl := time.Duration(req.GetTtlSeconds()) * time.Second
	if ttl == 0 {
		ttl = MaxTokenTTL
	}
	if ttl < time.Minute || ttl > MaxTokenTTL {
		return nil, status.Error(codes.InvalidArgument, "ttl_seconds must be between 60 and 86400")
	}
	secret := make([]byte, 32)
	idb := make([]byte, 10)
	if _, err := rand.Read(secret); err != nil {
		return nil, internal("token", err)
	}
	if _, err := rand.Read(idb); err != nil {
		return nil, internal("token", err)
	}
	token := "stet_" + strings.ToLower(tokenEncoding.EncodeToString(secret))
	id := "tok-" + strings.ToLower(tokenEncoding.EncodeToString(idb))
	expires := f.now().Add(ttl).UTC()
	err := f.store.CreateEnrollmentToken(ctx, id, req.GetGroupId(), token, expires, audit(ctx, "groups/"+req.GetGroupId()+"/enrollmentTokens/"+id))
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil, status.Error(codes.NotFound, "no such group")
	case err != nil:
		return nil, internal("create enrollment token", err)
	}
	return &adminv1.CreateEnrollmentTokenResponse{Id: id, GroupId: req.GetGroupId(), Token: token, ExpireTime: timestamppb.New(expires)}, nil
}

func (f *fleetAdmin) nodePB(n store.Node, now time.Time) *adminv1.Node {
	out := &adminv1.Node{
		Id: n.ID, GroupId: n.GroupID, Hostname: n.Hostname, ProxyVersion: n.ProxyVersion, ModuleVersion: n.ModuleVersion,
		BundleState: n.BundleState, Revoked: n.RevokedAt != nil, CreateTime: timestamppb.New(n.CreatedAt),
		Online: f.presence.Online(n.ID, n.Connected, n.LastSeenAt, n.RevokedAt != nil, now),
	}
	if n.BundleVersion != nil && *n.BundleVersion > 0 {
		out.BundleVersion = uint64(*n.BundleVersion)
	}
	if n.LastSeenAt != nil {
		out.LastSeenTime = timestamppb.New(*n.LastSeenAt)
	}
	if n.CertNotAfter != nil {
		out.CertExpireTime = timestamppb.New(*n.CertNotAfter)
	}
	return out
}

func (f *fleetAdmin) ListNodes(ctx context.Context, _ *adminv1.ListNodesRequest) (*adminv1.ListNodesResponse, error) {
	ns, err := f.store.ListNodes(ctx)
	if err != nil {
		return nil, internal("list nodes", err)
	}
	now := f.now()
	out := &adminv1.ListNodesResponse{}
	for _, n := range ns {
		out.Nodes = append(out.Nodes, f.nodePB(n, now))
	}
	return out, nil
}

func (f *fleetAdmin) RevokeNode(ctx context.Context, req *adminv1.RevokeNodeRequest) (*adminv1.RevokeNodeResponse, error) {
	id := req.GetNodeId()
	if id == "" || len(id) > 128 {
		return nil, status.Error(codes.InvalidArgument, "node_id is required")
	}
	n, err := f.store.RevokeNode(ctx, id, f.now(), audit(ctx, "nodes/"+id))
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil, status.Error(codes.NotFound, "no such node")
	case err != nil:
		return nil, internal("revoke node", err)
	}
	f.presence.Cut(id) // the streams end now; new ones are refused by the fleet interceptor
	return &adminv1.RevokeNodeResponse{Node: f.nodePB(n, f.now())}, nil
}
