export type UserRole = 'viewer' | 'operator' | 'approver' | 'admin';

const known: UserRole[] = ['viewer', 'operator', 'approver', 'admin'];

// rolesFromAccessToken reads realm_access.roles from the token payload. The
// signature is not checked here: the roles only decide what the UI shows,
// and the API checks every call again.
export function rolesFromAccessToken(token: string): UserRole[] {
  const part = token.split('.')[1];
  if (!part) return [];
  try {
    const b64 = part.replace(/-/g, '+').replace(/_/g, '/');
    const json = atob(b64 + '='.repeat((4 - (b64.length % 4)) % 4));
    const payload = JSON.parse(json) as { realm_access?: { roles?: unknown } };
    const roles = payload.realm_access?.roles;
    if (!Array.isArray(roles)) return [];
    return known.filter((r) => roles.includes(r));
  } catch {
    return [];
  }
}

// The role shown in the header: the strongest one held.
export function primaryRole(roles: UserRole[]): UserRole | undefined {
  for (const r of ['admin', 'approver', 'operator', 'viewer'] as UserRole[]) {
    if (roles.includes(r)) return r;
  }
  return undefined;
}

// canWritePolicies: the roles with policies:write in the control plane
// (control-plane/auth/rbac.go). Only hides the editor; the API checks.
export function canWritePolicies(roles: UserRole[]): boolean {
  return roles.includes('operator') || roles.includes('admin');
}

// canReadAudit: the roles with audit:read in the control plane (admin only)
export function canReadAudit(roles: UserRole[]): boolean {
  return roles.includes('admin');
}

// knownRoles keeps the four roles of a list (a local session's roles).
export function knownRoles(roles: string[]): UserRole[] {
  return known.filter((r) => roles.includes(r));
}

// UI visibility only; policies:approve is enforced again by the API.
export function canApprovePolicies(roles: UserRole[]): boolean {
  return roles.includes('approver') || roles.includes('admin');
}

// UI visibility only; events:write is enforced again by the API.
export function canWriteEvents(roles: UserRole[]): boolean {
  return roles.includes('operator') || roles.includes('admin');
}
