import { components } from './generated/schema';
import { components as admin } from './generated/admin';

export type Event = components['schemas']['Event'] & {
  country_iso?: string;
  city?: string;
  lat?: number;
  lon?: number;
  asn?: number;
  as_org?: string;
};
export type Violation = components['schemas']['Violation'];
export type SearchEventsRequest = components['schemas']['SearchEventsRequest'] & {
  country_iso?: string;
  asn?: number;
};
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

  /** POST /v1/policies/{id}:quick-rule (W19-G2-01) */
  async quickRule(policyId: string, req: QuickRuleRequest): Promise<QuickRuleResponse> {
    return call<QuickRuleResponse>(
      `/policies/${encodeURIComponent(policyId)}:quick-rule`,
      json('POST', req),
      'Failed to create quick rule'
    );
  },

  /** GET /v1/policies/{id}/versions, newest first */
  async listPolicyVersions(policyId: string): Promise<PolicyVersion[]> {
    const r = await call<admin['schemas']['v1ListPolicyVersionsResponse']>(
      `/policies/${encodeURIComponent(policyId)}/versions`, { method: 'GET' }, 'Failed to list versions');
    return r.versions ?? [];
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

  /** GET /v1/audit: list audit log entries with optional filters */
  async listAuditLogs(params?: number | { limit?: number; actor?: string; channel?: string; action?: string; resource?: string }): Promise<AuditEntry[]> {
    const q = new URLSearchParams();
    if (typeof params === 'number') {
      q.set('limit', String(params));
    } else if (params) {
      if (params.limit) q.set('limit', String(params.limit));
      if (params.actor) q.set('actor', params.actor);
      if (params.channel) q.set('channel', params.channel);
      if (params.action) q.set('action', params.action);
      if (params.resource) q.set('resource', params.resource);
    }
    const queryStr = q.toString() ? `?${q.toString()}` : '';
    const r = await call<ListAuditResponse>(`/audit${queryStr}`, { method: 'GET' }, 'Failed to list audit log');
    return r.entries ?? [];
  },

  /** GET /v1/service-accounts */
  async listServiceAccounts(): Promise<ServiceAccount[]> {
    const r = await call<{ service_accounts: ServiceAccount[] }>('/service-accounts', { method: 'GET' }, 'Failed to list service accounts');
    return r.service_accounts ?? [];
  },

  /** POST /v1/service-accounts */
  async createServiceAccount(sa: { name: string; description?: string; id?: string; roles?: string[] }): Promise<ServiceAccount> {
    const payload = {
      id: sa.id || sa.name.toLowerCase().replace(/[^a-z0-9_-]/g, '-'),
      name: sa.name,
      description: sa.description || '',
      roles: sa.roles || ['viewer'],
    };
    return call<ServiceAccount>('/service-accounts', {
      method: 'POST',
      body: JSON.stringify(payload),
    }, 'Failed to create service account');
  },

  /** DELETE /v1/service-accounts/{id} */
  async deleteServiceAccount(id: string): Promise<void> {
    await call<void>(`/service-accounts/${encodeURIComponent(id)}`, { method: 'DELETE' }, 'Failed to delete service account');
  },

  /** GET /v1/service-accounts/{id}/tokens */
  async listServiceAccountTokens(saId: string): Promise<ServiceAccountToken[]> {
    const r = await call<{ tokens: ServiceAccountToken[] }>(`/service-accounts/${encodeURIComponent(saId)}/tokens`, { method: 'GET' }, 'Failed to list tokens');
    return r.tokens ?? [];
  },

  /** POST /v1/service-accounts/{id}/tokens */
  async createServiceAccountToken(saId: string, req: { scopes: string[]; ttl_seconds?: number } | string[], ttlSeconds?: number): Promise<CreateTokenResponse> {
    const body = Array.isArray(req)
      ? { scopes: req, ttl_seconds: ttlSeconds }
      : { scopes: req.scopes, ttl_seconds: req.ttl_seconds };
    return call<CreateTokenResponse>(`/service-accounts/${encodeURIComponent(saId)}/tokens`, {
      method: 'POST',
      body: JSON.stringify(body),
    }, 'Failed to create token');
  },

  /** DELETE /v1/service-accounts/{id}/tokens/{tokenId} */
  async revokeServiceAccountToken(saId: string, tokenId: string): Promise<void> {
    await call<void>(`/service-accounts/${encodeURIComponent(saId)}/tokens/${encodeURIComponent(tokenId)}`, { method: 'DELETE' }, 'Failed to revoke token');
  },

  /** GET /v1/stats/geo */
  async getGeoStats(filter?: GeoStatsFilter): Promise<GeoStatsResponse> {
    const q = new URLSearchParams();
    if (filter?.from) q.set('from', filter.from);
    if (filter?.to) q.set('to', filter.to);
    if (filter?.groupBy) q.set('groupBy', filter.groupBy);
    if (filter?.policy_id) q.set('policy_id', filter.policy_id);
    if (filter?.action) q.set('action', filter.action);
    const qs = q.toString();
    return call<GeoStatsResponse>(`/stats/geo${qs ? '?' + qs : ''}`, { method: 'GET' }, 'Failed to fetch geo statistics');
  },

  /** GET /v1/stats/timeline */
  async getTimelineStats(filter?: TimelineFilter): Promise<TimelineResponse> {
    const q = new URLSearchParams();
    if (filter?.from) q.set('from', filter.from);
    if (filter?.to) q.set('to', filter.to);
    if (filter?.step) q.set('step', filter.step);
    if (filter?.policy_id) q.set('policy_id', filter.policy_id);
    if (filter?.country_iso) q.set('country_iso', filter.country_iso);
    if (filter?.asn) q.set('asn', String(filter.asn));
    if (filter?.action) q.set('action', filter.action);
    const qs = q.toString();
    return call<TimelineResponse>(`/stats/timeline${qs ? '?' + qs : ''}`, { method: 'GET' }, 'Failed to fetch timeline statistics');
  },

  /** GET /v1/stats/geo:watch (Server-Sent Events) */
  openGeoWatchStream(
    onUpdate: (data: GeoStatsResponse | { timestamp: string; countries: GeoCountryStat[]; asns: GeoASNStat[] }) => void,
    onError?: (err: globalThis.Event) => void
  ): () => void {
    if (typeof EventSource === 'undefined') {
      return () => {};
    }
    let es: EventSource | null = null;
    let closed = false;
    void handlers.token().then((tok) => {
      if (closed) return;
      const url = `/v1/stats/geo:watch${tok ? '?token=' + encodeURIComponent(tok) : ''}`;
      es = new EventSource(url);
      es.addEventListener('geo_snapshot', (e: MessageEvent) => {
        try {
          const data = JSON.parse(e.data);
          onUpdate(data);
        } catch (err) {
          console.error('Failed to parse geo_snapshot', err);
        }
      });
      es.addEventListener('geo_update', (e: MessageEvent) => {
        try {
          const data = JSON.parse(e.data);
          onUpdate(data);
        } catch (err) {
          console.error('Failed to parse geo_update', err);
        }
      });
      if (onError) {
        es.onerror = onError;
      }
    });

    return () => {
      closed = true;
      es?.close();
    };
  },
};

export interface GeoCountryStat {
  country_iso: string;
  events: number;
  blocked: number;
  top_attack_type: string;
}

export interface GeoASNStat {
  asn: number;
  as_org: string;
  events: number;
  blocked: number;
}

export interface GeoGridStat {
  geohash: string;
  lat: number;
  lon: number;
  city: string;
  country_iso: string;
  events: number;
  blocked: number;
  top_attack_type: string;
}

export interface GeoStatsResponse {
  from: string;
  to: string;
  countries?: GeoCountryStat[];
  asns?: GeoASNStat[];
  grid?: GeoGridStat[];
}

export interface GeoStatsFilter {
  from?: string;
  to?: string;
  groupBy?: string;
  policy_id?: string;
  action?: string;
}

export interface TimelineBucket {
  timestamp: string;
  total: number;
  blocked: number;
  monitored: number;
  passed: number;
  challenged?: number;
  attack_types?: Record<string, number>;
}

export interface TimelineResponse {
  from: string;
  to: string;
  step: string;
  buckets: TimelineBucket[];
}

export interface TimelineFilter {
  from?: string;
  to?: string;
  step?: string;
  policy_id?: string;
  country_iso?: string;
  asn?: number;
  action?: string;
}

export interface ServiceAccount {
  id: string;
  name: string;
  description?: string;
  roles: string[];
  created_at: string;
  created_by?: string;
  updated_at?: string;
  token_count?: number;
}

export interface ServiceAccountToken {
  id: string;
  service_account_id: string;
  token_prefix: string;
  scopes: string[];
  expires_at: string;
  created_at: string;
  last_used_at?: string;
  revoked?: boolean;
}

export interface CreateTokenResponse {
  raw_token: string;
  token: ServiceAccountToken;
}

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

export interface QuickRuleRequest {
  type: 'geo' | 'asn';
  target: string;
  action: 'block' | 'challenge';
  reason?: string;
}

export interface QuickRuleResponse {
  policy_id: string;
  version: number;
  etag: string;
  message: string;
}

