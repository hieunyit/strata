package auth

import (
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func rpcString(m protoreflect.Message, name string) string {
	field := m.Descriptor().Fields().ByName(protoreflect.Name(name))
	if field == nil || field.Kind() != protoreflect.StringKind {
		return ""
	}
	return m.Get(field).String()
}

// ScopedRPC is an allowlist: new global RPCs cannot accidentally bypass scopes.
func (p *Principal) ScopedRPC(method string, req any, perm Permission) bool {
	if p.Access == nil {
		return true
	}
	parts := strings.Split(method, "/")
	name := parts[len(parts)-1]
	switch name {
	case "GetVersion", "ListPolicyTemplates", "ListPolicies", "ListNodes", "ListGroups", "ListBundles", "ListRollouts", "ListCommands":
		return true
	}
	msg, ok := req.(proto.Message)
	if !ok {
		return false
	}
	m := msg.ProtoReflect()
	policy := rpcString(m, "policy_id")
	if field := m.Descriptor().Fields().ByName("policy"); policy == "" && field != nil && field.Kind() == protoreflect.MessageKind {
		policy = rpcString(m.Get(field).Message(), "id")
	}
	switch name {
	case "GetPolicy", "UpdatePolicy", "GetPolicyVersion", "ListPolicyVersions", "ReplayPolicy", "GetPolicyVersionReplay", "SubmitPolicy", "ApprovePolicy", "RejectPolicy", "DeployPolicy":
		if name == "ListPolicyVersions" && policy == "-" {
			return true
		}
		return policy != "" && p.CanResource("policies/"+policy, perm)
	case "GetOperation":
		return p.CanResource("operations/"+rpcString(m, "operation_id"), perm)
	case "GetCommand":
		return p.CanResource("commands/"+rpcString(m, "command_id"), perm)
	}
	return false
}

func (p *Principal) FilterRPC(method string, response any) any {
	if p.Access == nil {
		return response
	}
	msg, ok := response.(proto.Message)
	if !ok {
		return response
	}
	out := proto.Clone(msg)
	m := out.ProtoReflect()
	names := map[string]struct{ field, resource, id string }{
		"ListPolicies": {"policies", "policies", "id"}, "ListNodes": {"nodes", "nodes", "id"}, "ListGroups": {"groups", "groups", "id"},
		"ListPolicyVersions": {"versions", "policies", "policy_id"}, "ListCommands": {"commands", "nodes", "node_id"},
		// Global bundles/rollouts include other applications; do not disclose them.
		"ListBundles": {"bundles", "bundles", "version"}, "ListRollouts": {"rollouts", "rollouts", "id"},
	}
	parts := strings.Split(method, "/")
	selection, ok := names[parts[len(parts)-1]]
	if !ok {
		return response
	}
	field := m.Descriptor().Fields().ByName(protoreflect.Name(selection.field))
	if field == nil || !field.IsList() {
		return response
	}
	list := m.Mutable(field).List()
	keep := []protoreflect.Value{}
	for i := 0; i < list.Len(); i++ {
		v := list.Get(i)
		id := rpcString(v.Message(), selection.id)
		resource := selection.resource + "/" + id
		for perm, allowed := range p.Access.Resources[resource] {
			if allowed && p.Can(perm) {
				keep = append(keep, v)
				break
			}
		}
	}
	list.Truncate(0)
	for _, v := range keep {
		list.Append(v)
	}
	return out
}
