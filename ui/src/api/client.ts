import { components } from './generated/schema';
import { components as admin } from './generated/admin';

export type Event = components['schemas']['Event'];
export type Violation = components['schemas']['Violation'];
export type SearchEventsRequest = components['schemas']['SearchEventsRequest'];
export type SearchEventsResponse = components['schemas']['SearchEventsResponse'];
export type GetEventResponse = components['schemas']['GetEventResponse'];
export type GetVersionResponse = admin['schemas']['v1GetVersionResponse'];
export type Policy = admin['schemas']['v1Policy'];
export type PolicyVersion = admin['schemas']['v1PolicyVersion'];
export type PolicySpec = admin['schemas']['v1PolicySpec'];
export type Group = admin['schemas']['v1Group'];
export type FleetNode = admin['schemas']['v1Node'];
export type Rollout = admin['schemas']['v1Rollout'];
export type RolloutNode = admin['schemas']['v1RolloutNode'];
export type Operation = admin['schemas']['v1Operation'];
export type ReplayComparison = admin['schemas']['v1ReplayComparison'];
export type ReplayExample = admin['schemas']['v1ReplayExample'];
export type ErrorResponse = components['schemas']['ErrorResponse'];
export type Overview = components['schemas']['OverviewResponse'];
export type OverviewBucket = components['schemas']['OverviewBucket'];
export type RuleInfo = components['schemas']['RuleInfo'];
export type AuthMethods = components['schemas']['AuthMethods'];
export type LocalSession = components['schemas']['LocalSession'];
export type Me = components['schemas']['Me'];
export type LocalUser = components['schemas']['User'];
export type CreateUserRequest = components['schemas']['CreateUserRequest'];
export type UpdateUserRequest = components['schemas']['UpdateUserRequest'];

export interface OverviewParams {
  from: string;
  to: string;
  policy_id?: string;
}

export class ApiError extends Error {
  code: number;
  blockId?: string;

  constructor(message: string, code: number, blockId?: string) {
    super(message);
    this.name = 'ApiError';
    this.code = code;
    this.blockId = blockId;
  }
}

const API_BASE = '/v1';

interface AuthHandlers {
  token: () => Promise<string | undefined>;
  unauthorized: () => void;
}

let handlers: AuthHandlers = { token: async () => undefined, unauthorized: () => {} };

// setAuthHandlers is called by AuthProvider: every request carries the
// current access token, and a 401 ends the session.
export function setAuthHandlers(h: AuthHandlers): void {
  handlers = h;
}

async function call<T>(path: string, init: RequestInit, fallback: string): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set('Accept', 'application/json');
  const token = await handlers.token();
  if (token) headers.set('Authorization', `Bearer ${token}`);
  const res = await fetch(`${API_BASE}${path}`, { ...init, headers });
  if (!res.ok) {
    let errPayload: ErrorResponse = { error: `Request failed with status ${res.status}` };
    try {
      errPayload = await res.json();
    } catch {
      // use default error
    }
    if (res.status === 401) handlers.unauthorized();
    // the admin API (grpc-gateway) answers {code, message}, the REST API {error}
    const message = errPayload.error || (errPayload as { message?: string }).message;
    throw new ApiError(message || fallback, res.status, errPayload.block_id);
  }
  if (res.status === 204) return undefined as T;
  return res.json();
}

const json = (method: string, body: unknown): RequestInit => ({
  method,
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(body),
});

// The sign-in methods, asked before there is any session. An older control
// plane without the route only knows OIDC.
export async function fetchAuthMethods(fetchFn: typeof fetch = fetch): Promise<AuthMethods> {
  try {
    const res = await fetchFn(`${API_BASE}/auth/methods`, { headers: { Accept: 'application/json' }, cache: 'no-store' });
    if (!res.ok) return { local: false, oidc: true };
    const body = (await res.json()) as Partial<AuthMethods>;
    return { local: body.local === true, oidc: body.oidc !== false };
  } catch {
    return { local: false, oidc: true };
  }
}

// POST /v1/auth/login: no token, and a 401 here is a wrong password, not
// an expired session.
export async function localLogin(username: string, password: string): Promise<LocalSession> {
  const res = await fetch(`${API_BASE}/auth/login`, {
    ...json('POST', { username, password }),
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
  });
  if (!res.ok) {
    let msg = `Request failed with status ${res.status}`;
    try {
      msg = ((await res.json()) as ErrorResponse).error || msg;
    } catch {
      // keep the default
    }
    throw new ApiError(msg, res.status);
  }
  return res.json();
}

export const apiClient = {
  /** POST /v1/events:search */
  searchEvents(params: SearchEventsRequest): Promise<SearchEventsResponse> {
    return call('/events:search', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(params),
    }, 'Failed to search events');
  },

  /** GET /v1/events/{block_id}: the decision trace of one event */
  getEvent(blockId: string): Promise<GetEventResponse> {
    const id = encodeURIComponent(blockId.trim().toUpperCase());
    return call(`/events/${id}`, { method: 'GET' }, 'Failed to get event');
  },

  /** GET /v1/stats/overview: the Overview page's statistics (W10-F-01) */
  getOverview(p: OverviewParams): Promise<Overview> {
    const q = new URLSearchParams({ from: p.from, to: p.to });
    if (p.policy_id) q.set('policy_id', p.policy_id);
    return call(`/stats/overview?${q}`, { method: 'GET' }, 'Failed to load statistics');
  },

  /** POST /v1/auth/logout: ends a local session */
  logout(): Promise<void> {
    return call('/auth/logout', { method: 'POST' }, 'Failed to sign out');
  },

  /** GET /v1/auth/me */
  me(): Promise<Me> {
    return call('/auth/me', { method: 'GET' }, 'Failed to read the session');
  },

  /** POST /v1/auth/password: a local account changes its own password */
  changePassword(current: string, next: string): Promise<void> {
    return call('/auth/password', json('POST', { current_password: current, new_password: next }), 'Failed to change the password');
  },

  /** GET /v1/users: local accounts */
  async listUsers(): Promise<LocalUser[]> {
    const r = await call<components['schemas']['ListUsersResponse']>('/users', { method: 'GET' }, 'Failed to list users');
    return r.users ?? [];
  },

  /** POST /v1/users */
  async createUser(req: CreateUserRequest): Promise<LocalUser> {
    const r = await call<components['schemas']['UserResponse']>('/users', json('POST', req), 'Failed to create the user');
    return r.user;
  },

  /** PATCH /v1/users/{username} */
  async updateUser(username: string, req: UpdateUserRequest): Promise<LocalUser> {
    const r = await call<components['schemas']['UserResponse']>(
      `/users/${encodeURIComponent(username)}`, json('PATCH', req), 'Failed to update the user');
    return r.user;
  },

  /** DELETE /v1/users/{username} */
  deleteUser(username: string): Promise<void> {
    return call(`/users/${encodeURIComponent(username)}`, { method: 'DELETE' }, 'Failed to delete the user');
  },

  /** GET /v1/version */
  getVersion(): Promise<GetVersionResponse> {
    return call('/version', { method: 'GET' }, 'Failed to get version');
  },

  /** GET /v1/policies */
  async listPolicies(): Promise<Policy[]> {
    const r = await call<admin['schemas']['v1ListPoliciesResponse']>('/policies', { method: 'GET' }, 'Failed to list policies');
    return r.policies ?? [];
  },

  /** PATCH /v1/policies/{id}: a new version (DRAFT) from the etag it was read with; 409 when stale */
  async updatePolicy(policyId: string, spec: PolicySpec, etag: string): Promise<Policy> {
    const r = await call<admin['schemas']['v1UpdatePolicyResponse']>(
      `/policies/${encodeURIComponent(policyId)}`, json('PATCH', { etag, spec }), 'Failed to save the policy');
    return r.policy ?? {};
  },

  /** GET /v1/policies/{id}/versions, newest first */
  async listPolicyVersions(policyId: string): Promise<PolicyVersion[]> {
    const r = await call<admin['schemas']['v1ListPolicyVersionsResponse']>(
      `/policies/${encodeURIComponent(policyId)}/versions`, { method: 'GET' }, 'Failed to list versions');
    return r.versions ?? [];
  },

  /** GET /v1/policies/-/versions?state=: versions of every policy in a state (the review queue: SUBMITTED) */
  async listVersionsByState(state: string): Promise<PolicyVersion[]> {
    const r = await call<admin['schemas']['v1ListPolicyVersionsResponse']>(
      `/policies/-/versions?state=${encodeURIComponent(state)}`, { method: 'GET' }, 'Failed to list versions');
    return r.versions ?? [];
  },

  /** POST /v1/policies/{id}:submit: a DRAFT or REJECTED version up for review (W13-G2-02) */
  async submitPolicy(policyId: string, version: number): Promise<PolicyVersion> {
    const r = await call<admin['schemas']['v1SubmitPolicyResponse']>(
      `/policies/${encodeURIComponent(policyId)}:submit`, json('POST', { version }), 'Failed to submit the version');
    return r.version ?? {};
  },

  /** POST /v1/policies/{id}:approve: someone other than its author; needs a DONE replay */
  async approvePolicy(policyId: string, version: number, comment: string): Promise<PolicyVersion> {
    const r = await call<admin['schemas']['v1ApprovePolicyResponse']>(
      `/policies/${encodeURIComponent(policyId)}:approve`, json('POST', { version, comment }), 'Failed to approve the version');
    return r.version ?? {};
  },

  /** POST /v1/policies/{id}:reject: with the reason */
  async rejectPolicy(policyId: string, version: number, comment: string): Promise<PolicyVersion> {
    const r = await call<admin['schemas']['v1RejectPolicyResponse']>(
      `/policies/${encodeURIComponent(policyId)}:reject`, json('POST', { version, comment }), 'Failed to reject the version');
    return r.version ?? {};
  },

  /** GET /v1/policies/{id}/versions/{v}/replay: the newest replay of a version (W13-G2-01); undefined when none */
  async getVersionReplay(policyId: string, version: number): Promise<Operation | undefined> {
    try {
      const r = await call<admin['schemas']['v1GetPolicyVersionReplayResponse']>(
        `/policies/${encodeURIComponent(policyId)}/versions/${version}/replay`, { method: 'GET' }, 'Failed to read the replay');
      return r.operation;
    } catch (e) {
      if (e instanceof ApiError && e.code === 404) return undefined;
      throw e;
    }
  },

  /** POST /v1/policies/{id}:replay: replays a version again */
  async replayPolicy(policyId: string, version: number): Promise<Operation | undefined> {
    const r = await call<admin['schemas']['v1ReplayPolicyResponse']>(
      `/policies/${encodeURIComponent(policyId)}:replay`, json('POST', { version }), 'Failed to start the replay');
    return r.operation;
  },

  /** GET /v1/groups */
  async listGroups(): Promise<Group[]> {
    const r = await call<admin['schemas']['v1ListGroupsResponse']>('/groups', { method: 'GET' }, 'Failed to list groups');
    return r.groups ?? [];
  },

  /** GET /v1/nodes */
  async listNodes(): Promise<FleetNode[]> {
    const r = await call<admin['schemas']['v1ListNodesResponse']>('/nodes', { method: 'GET' }, 'Failed to list nodes');
    return r.nodes ?? [];
  },

  /** GET /v1/rollouts, newest first */
  async listRollouts(): Promise<Rollout[]> {
    const r = await call<admin['schemas']['v1ListRolloutsResponse']>('/rollouts', { method: 'GET' }, 'Failed to list rollouts');
    return r.rollouts ?? [];
  },

  /** GET /v1/rollouts/{id}: with the state of each node */
  async getRollout(id: string): Promise<Rollout | undefined> {
    const r = await call<admin['schemas']['v1GetRolloutResponse']>(
      `/rollouts/${encodeURIComponent(id)}`, { method: 'GET' }, 'Failed to get rollout');
    return r.rollout;
  },
};
