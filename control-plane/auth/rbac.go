package auth

import "sort"

// Role is one of the four admin roles (nginx-module.md › API quản trị ›
// Xác thực và phân quyền).
type Role string

const (
	RoleViewer   Role = "viewer"
	RoleOperator Role = "operator"
	RoleApprover Role = "approver"
	RoleAdmin    Role = "admin"
)

// Roles lists the roles in a stable order.
var Roles = []Role{RoleViewer, RoleOperator, RoleApprover, RoleAdmin}

// Permission is checked by every admin endpoint. Unknown permissions are
// granted to nobody.
type Permission string

const (
	PermVersionRead         Permission = "version:read"
	PermEventsRead          Permission = "events:read"
	PermEventsReadSensitive Permission = "events:read_sensitive" // full client IPs and input snippets
	PermPoliciesRead        Permission = "policies:read"
	PermPoliciesWrite       Permission = "policies:write"
	PermPoliciesApprove     Permission = "policies:approve"
	PermPoliciesDeploy      Permission = "policies:deploy"
	// PermRulesDisable: the emergency kill switch (W12-G2-02), operator
	// and above.
	PermRulesDisable      Permission = "rules:disable"
	PermExceptionsWrite   Permission = "exceptions:write"
	PermNodesRead         Permission = "nodes:read"
	PermNodesWrite        Permission = "nodes:write" // enrollment tokens, revocation
	PermRoleBindingsRead  Permission = "rolebindings:read"
	PermRoleBindingsWrite Permission = "rolebindings:write"
	PermAuditRead         Permission = "audit:read"
)

var (
	viewerPerms = []Permission{
		PermVersionRead, PermEventsRead, PermPoliciesRead, PermNodesRead,
	}
	matrix = map[Role][]Permission{
		RoleViewer: viewerPerms,
		RoleOperator: append(append([]Permission{}, viewerPerms...),
			PermEventsReadSensitive, PermPoliciesWrite, PermPoliciesDeploy, PermExceptionsWrite, PermRulesDisable),
		// The approver reviews what an operator drafted; it does not draft
		// or deploy itself.
		RoleApprover: append(append([]Permission{}, viewerPerms...),
			PermEventsReadSensitive, PermPoliciesApprove, PermRulesDisable),
		RoleAdmin: append(append([]Permission{}, viewerPerms...),
			PermEventsReadSensitive, PermPoliciesWrite, PermPoliciesApprove, PermPoliciesDeploy,
			PermExceptionsWrite, PermNodesWrite, PermRoleBindingsRead, PermRoleBindingsWrite, PermAuditRead, PermRulesDisable),
	}
)

// Allows reports whether role r grants p.
func (r Role) Allows(p Permission) bool {
	for _, q := range matrix[r] {
		if q == p {
			return true
		}
	}
	return false
}

// ParseRoles keeps the known roles of names, sorted and without duplicates.
func ParseRoles(names []string) []Role {
	seen := map[Role]bool{}
	for _, n := range names {
		r := Role(n)
		if _, ok := matrix[r]; ok {
			seen[r] = true
		}
	}
	out := make([]Role, 0, len(seen))
	for r := range seen {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
