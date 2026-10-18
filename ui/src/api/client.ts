import { components, operations } from './generated/schema';
import { components as admin } from './generated/admin';

export type MarkFalsePositiveRequest = operations['markFalsePositive']['requestBody']['content']['application/json'];
export type MarkFalsePositiveResponse = operations['markFalsePositive']['responses'][200]['content']['application/json'];

export type Event = components['schemas']['Event'];
export type Violation = components['schemas']['Violation'];
export type SearchEventsRequest = components['schemas']['SearchEventsRequest'];
export type SearchEventsResponse = components['schemas']['SearchEventsResponse'];
export type GetEventResponse = components['schemas']['GetEventResponse'];
export type GetVersionResponse = admin['schemas']['v1GetVersionResponse'];
export type Policy = admin['schemas']['v1Policy'];
export type PolicyVersion = admin['schemas']['v1PolicyVersion'];
export type Operation = admin['schemas']['v1Operation'];
export type ReplayReport = admin['schemas']['v1ReplayReport'];
export type ReplayComparison = admin['schemas']['v1ReplayComparison'];
export type ReplayExample = admin['schemas']['v1ReplayExample'];
export type PolicySpec = admin['schemas']['v1PolicySpec'];
export type Group = admin['schemas']['v1Group'];
export type FleetNode = admin['schemas']['v1Node'];
export type Rollout = admin['schemas']['v1Rollout'];
export type RolloutNode = admin['schemas']['v1RolloutNode'];
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

export type ExceptionFromBlockRequest = components['schemas']['ExceptionFromBlockRequest'];
export type ExceptionDraftResponse = components['schemas']['ExceptionDraftResponse'];
export type RuleStagingNotice = components['schemas']['RuleStagingNotice'];
export type RuleStagingNoticePage = components['schemas']['RuleStagingNoticePage'];

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
    throw new ApiError(errPayload.error || fallback, res.status, errPayload.block_id);
  }
  if (res.status === 204) return undefined as T;
  return res.json();
}

const json = (method: string, body: unknown): RequestInit => ({
  method,
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(body),
});

// Version 0 means "latest" on some RPCs. Review actions must never fall back
// to a different version from the one the user inspected.
function validVersion(version: unknown): version is number {
  return typeof version === 'number' && Number.isInteger(version) && version >= 1 && version <= 0xffffffff;
}
function explicitVersion(version: number): void {
  if (!validVersion(version)) throw new ApiError('An explicit policy version is required', 400);
}
function versionReceipt(value: PolicyVersion | undefined, id: string, version: number, state: string): PolicyVersion {
  if (!value || value.policy_id !== id || value.version !== version || value.state !== state) throw new ApiError('Invalid policy version receipt; reload before retrying', 502);
  return value;
}
function operationReceipt(value: Operation | undefined, id: string, version: number): Operation {
  if (!value?.id || value.kind !== 'REPLAY' || value.policy_id !== id || value.version !== version ||
      !['PENDING', 'RUNNING', 'DONE', 'FAILED'].includes(value.state ?? '') ||
      (value.state === 'DONE' && (!value.done || !value.replay))) throw new ApiError('Invalid replay operation', 502);
  return value;
}

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
  async markFalsePositive(blockId: string, command: MarkFalsePositiveRequest): Promise<MarkFalsePositiveResponse> {
    return call<MarkFalsePositiveResponse>(`/events/${encodeURIComponent(blockId)}:markFalsePositive`, json('POST', command), 'Failed to classify the event');
  },

  async listRuleStagingNotices(cursor = '', signal?: AbortSignal): Promise<RuleStagingNoticePage> {
    const query = new URLSearchParams({ limit: '20' });
    if (cursor) query.set('cursor', cursor);
    return call<RuleStagingNoticePage>(`/rules/staging-actions?${query}`, { method: 'GET', signal }, 'Failed to read staging notices');
  },

  createExceptionFromBlock(request: ExceptionFromBlockRequest): Promise<ExceptionDraftResponse> {
    return call('/exceptions:fromBlockId', json('POST', request), 'Failed to create exception draft');
  },
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
  async listPolicies(signal?: AbortSignal): Promise<Policy[]> {
    const r = await call<admin['schemas']['v1ListPoliciesResponse']>('/policies', { method: 'GET', signal }, 'Failed to list policies');
    return r.policies ?? [];
  },

  /** PATCH /v1/policies/{id}: a new version (DRAFT) from the etag it was read with; 409 when stale */
  async updatePolicy(policyId: string, spec: PolicySpec, etag: string): Promise<Policy> {
    const r = await call<admin['schemas']['v1UpdatePolicyResponse']>(
      `/policies/${encodeURIComponent(policyId)}`, json('PATCH', { etag, spec }), 'Failed to save the policy');
    return r.policy ?? {};
  },

  /** GET /v1/policies/{id}/versions, newest first */
  async listPolicyVersions(policyId: string, signal?: AbortSignal): Promise<PolicyVersion[]> {
    const r = await call<admin['schemas']['v1ListPolicyVersionsResponse']>(
      `/policies/${encodeURIComponent(policyId)}/versions`, { method: 'GET', signal }, 'Failed to list versions');
    return r.versions ?? [];
  },

  async listSubmittedPolicyVersions(signal?: AbortSignal): Promise<PolicyVersion[]> {
    const r = await call<admin['schemas']['v1ListPolicyVersionsResponse']>(
      '/policies/-/versions?state=SUBMITTED', { method: 'GET', signal }, 'Failed to read review queue');
    const rows = r.versions ?? [];
    if (!Array.isArray(rows) || rows.some((v) => !v || typeof v.policy_id !== 'string' || !v.policy_id || !validVersion(v.version) || v.state !== 'SUBMITTED')) throw new ApiError('Invalid review queue', 502);
    return rows;
  },

  async submitPolicy(id: string, version: number): Promise<PolicyVersion> {
    explicitVersion(version);
    const r = await call<admin['schemas']['v1SubmitPolicyResponse']>(
      `/policies/${encodeURIComponent(id)}:submit`, json('POST', { version }), 'Failed to submit version');
    return versionReceipt(r.version, id, version, 'SUBMITTED');
  },
  async approvePolicy(id: string, version: number, comment = '', expectedReplayId?: string): Promise<PolicyVersion> {
    explicitVersion(version);
    const body: admin['schemas']['PolicyServiceApprovePolicyBody'] = { version, comment, expected_replay_id: expectedReplayId };
    const r = await call<admin['schemas']['v1ApprovePolicyResponse']>(
      `/policies/${encodeURIComponent(id)}:approve`, json('POST', body), 'Failed to approve version');
    const approved = versionReceipt(r.version, id, version, 'APPROVED');
    if (expectedReplayId && approved.approved_replay_id !== expectedReplayId) throw new ApiError('Approval receipt has a different replay proof', 502);
    return approved;
  },
  async rejectPolicy(id: string, version: number, comment: string): Promise<PolicyVersion> {
    explicitVersion(version);
    if (!comment.trim()) throw new ApiError('A rejection reason is required', 400);
    const r = await call<admin['schemas']['v1RejectPolicyResponse']>(
      `/policies/${encodeURIComponent(id)}:reject`, json('POST', { version, comment }), 'Failed to reject version');
    return versionReceipt(r.version, id, version, 'REJECTED');
  },
  async getVersionReplay(id: string, version: number, signal?: AbortSignal): Promise<Operation | undefined> {
    explicitVersion(version);
    try {
      const r = await call<admin['schemas']['v1GetPolicyVersionReplayResponse']>(
        `/policies/${encodeURIComponent(id)}/versions/${version}/replay`, { method: 'GET', signal }, 'Failed to read replay');
      return operationReceipt(r.operation, id, version);
    } catch (e) {
      if (e instanceof ApiError && e.code === 404) return undefined;
      throw e;
    }
  },
  async replayPolicy(id: string, version: number): Promise<Operation> {
    explicitVersion(version);
    const r = await call<admin['schemas']['v1ReplayPolicyResponse']>(
      `/policies/${encodeURIComponent(id)}:replay`, json('POST', { version }), 'Failed to start replay');
    return operationReceipt(r.operation, id, version);
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

  /** DELETE /v1/nodes/{id}: revokes a node's mTLS certificate and access */
  async revokeNode(nodeId: string): Promise<FleetNode> {
    const r = await call<admin['schemas']['v1RevokeNodeResponse']>(
      `/nodes/${encodeURIComponent(nodeId)}`, { method: 'DELETE' }, 'Failed to revoke node');
    return r.node ?? {};
  },

  /** GET /v1/audit: list newest audit log entries */
  async listAuditLogs(limit = 100): Promise<AuditEntry[]> {
    const r = await call<ListAuditResponse>(`/audit?limit=${limit}`, { method: 'GET' }, 'Failed to list audit log');
    return r.entries ?? [];
  },
};

export interface AuditEntry {
  at?: string;
  actor: string;
  subject?: string;
  channel: string;
  action: string;
  resource: string;
  request_id?: string;
  before?: unknown;
  after?: unknown;
}

export interface ListAuditResponse {
  entries: AuditEntry[];
}

