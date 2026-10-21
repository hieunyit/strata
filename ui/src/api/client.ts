import { components, operations } from './generated/schema';
import { components as admin } from './generated/admin';
import { SseParser, SseEvent } from '../lib/sse';

export type MarkFalsePositiveRequest = operations['markFalsePositive']['requestBody']['content']['application/json'];
export type MarkFalsePositiveResponse = operations['markFalsePositive']['responses'][200]['content']['application/json'];

export type SavedSearchInput = components['schemas']['SavedSearchInput'];
export type SavedSearch = components['schemas']['SavedSearch'];
export type EventCase = components['schemas']['EventCase'];
export type EvidenceExport = components['schemas']['EvidenceExport'];
export type EventRuleRequest = components['schemas']['EventRuleRequest'];
export type EventRuleDraft = components['schemas']['EventRuleDraft'];
export type RuleCatalogEntry = components['schemas']['RuleCatalogEntry'];
export type RuleCatalogPage = components['schemas']['RuleCatalogPage'];
export type RuleCatalogDetail = components['schemas']['RuleCatalogDetail'];
export type RuleCatalogSnapshot = components['schemas']['RuleCatalogSnapshot'];
export type RuleCatalogDiff = components['schemas']['RuleCatalogDiff'];
export type ExceptionInventoryPage = components['schemas']['ExceptionInventoryPage'];
export type ExceptionLifecycleRequest = components['schemas']['ExceptionLifecycleRequest'];
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
export type PolicyTemplate = admin['schemas']['v1PolicyTemplate'];
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
export type MFAStatus = components['schemas']['MFAStatus'];
export type MFAEnrollment = components['schemas']['MFAEnrollment'];
export type MFACommand = components['schemas']['MFACommand'];
export type MFARecovery = components['schemas']['MFARecovery'];
export type OwnSession = components['schemas']['OwnSession'];
export type Release = components['schemas']['Release'];
export type ReleaseDetail = components['schemas']['ReleaseDetail'];
export type HealthSnapshot = components['schemas']['HealthSnapshot'];
export type HealthCheck = components['schemas']['HealthCheck'];
export type Application = components['schemas']['Application'];
export type ApplicationBinding = components['schemas']['ApplicationBinding'];
export type Me = components['schemas']['Me'];
export type LocalUser = components['schemas']['User'];
export type CreateUserRequest = components['schemas']['CreateUserRequest'];
export type UpdateUserRequest = components['schemas']['UpdateUserRequest'];

export type ExceptionFromBlockRequest = components['schemas']['ExceptionFromBlockRequest'];
export type ExceptionDraftResponse = components['schemas']['ExceptionDraftResponse'];
export type RuleStagingNotice = components['schemas']['RuleStagingNotice'];
export type RuleStagingNoticePage = components['schemas']['RuleStagingNoticePage'];
export type GeoCount = components['schemas']['GeoCount'];
export type GeoResponse = components['schemas']['GeoResponse'];
export type GeoBucket = components['schemas']['GeoBucket'];
export type TimelineResponse = components['schemas']['TimelineResponse'];
export type GeoSnapshot = components['schemas']['GeoSnapshot'];
export type GeoDelta = components['schemas']['GeoDelta'];
export type AttackType = components['schemas']['AttackType'];
export type GeoGroupBy = GeoResponse['group_by'];

/** filters of the map's statistics (W18-G2-01) */
export interface GeoFilters {
  policy_id?: string;
  action?: string;
  attack_type?: string;
  country?: string;
  asn?: string;
}

function geoQuery(f: GeoFilters, extra: Record<string, string | undefined>): URLSearchParams {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries({ ...f, ...extra })) {
    if (v) q.set(k, v);
  }
  return q;
}

export interface OverviewParams {
  from: string;
  to: string;
  policy_id?: string;
}

export class ApiError extends Error {
  code: number;
  blockId?: string;
  /** Machine-readable cause, e.g. EVENTS_UNAVAILABLE */
  reason?: string;

  constructor(message: string, code: number, blockId?: string, reason?: string) {
    super(message);
    this.name = 'ApiError';
    this.code = code;
    this.blockId = blockId;
    this.reason = reason;
  }
}

/** The event store (ClickHouse) did not answer: show "data source
 * unavailable", never an empty result (CP-A08). */
export function isEventsUnavailable(e: unknown): boolean {
  return e instanceof ApiError && e.reason === 'EVENTS_UNAVAILABLE';
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

async function call<T>(path: string, init: RequestInit, fallback: string, blob = false): Promise<T> {
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
    const reason = (errPayload as { reason?: unknown }).reason;
    throw new ApiError(errPayload.error || fallback, res.status, errPayload.block_id, typeof reason === 'string' ? reason : undefined);
  }
  if (res.status === 204) return undefined as T;
  return blob ? res.blob() as Promise<T> : res.json();
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
export async function localLogin(username: string, password: string, code = '', recovery = false): Promise<LocalSession> {
	const command: components['schemas']['LoginRequest'] = {username,password,code,recovery};
  const res = await fetch(`${API_BASE}/auth/login`, {
    ...json('POST', command),
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
  });
  if (!res.ok) {
    let msg = `Request failed with status ${res.status}`;
    let reason: string | undefined;
    try {
      const body = (await res.json()) as ErrorResponse;
      msg = body.error || msg;
      reason = body.reason;
    } catch {
      // keep the default
    }
    throw new ApiError(msg, res.status,undefined,reason);
  }
  return res.json();
}

export type OperationalIncidentPage=components['schemas']['OperationalIncidentPage'];
export type ReportScheduleReply=components['schemas']['ReportScheduleReply'];
export type ApplicationReport=components['schemas']['ApplicationReport'];
export type ReportScheduleRequest=components['schemas']['ReportScheduleRequest'];
const operationQuery=(application:string,environment:string)=>new URLSearchParams({application_id:application,environment_id:environment}).toString();
export const apiClient = {
  incidents(application:string,environment:string):Promise<OperationalIncidentPage>{return call(`/incidents?${operationQuery(application,environment)}`,{method:'GET'},'Incidents unavailable');},
  acknowledgeIncident(request:components['schemas']['IncidentAcknowledgeRequest']):Promise<components['schemas']['OperationalIncident']>{return call('/incidents:acknowledge',json('POST',request),'Acknowledge failed');},
  reportSchedule(application:string,environment:string):Promise<ReportScheduleReply>{return call(`/report-schedule?${operationQuery(application,environment)}`,{method:'GET'},'Schedule unavailable');},
  saveReportSchedule(request:ReportScheduleRequest):Promise<ReportScheduleReply>{return call('/report-schedule',json('PUT',request),'Schedule unavailable');},
  async applicationReports(application:string,environment:string):Promise<ApplicationReport[]>{return (await call<components['schemas']['ApplicationReportPage']>(`/application-reports?${operationQuery(application,environment)}`,{method:'GET'},'Reports unavailable')).reports;},
  downloadApplicationReport(id:string,application:string,environment:string):Promise<Blob>{return call(`/application-reports/${encodeURIComponent(id)}?${operationQuery(application,environment)}`,{method:'GET'},'Report unavailable',true);},
  ruleCatalog(filters: {source?: string; cve?: string; attack_type?: string; after?: string}): Promise<RuleCatalogPage> {
    const q = new URLSearchParams();for(const [key,value] of Object.entries(filters)) if(value) q.set(key,value);
    return call(`/rule-catalog?${q}`,{method:'GET'},'Rule catalog unavailable');
  },
  async catalogHistory(): Promise<RuleCatalogSnapshot[]> {
    return (await call<components['schemas']['RuleCatalogHistory']>('/rule-catalogs',{method:'GET'},'Catalog history unavailable')).catalogs;
  },
  catalogDiff(from: string,to: string,after = ''): Promise<RuleCatalogDiff> {
    return call(`/rule-catalogs:diff?${new URLSearchParams({from,to,after})}`,{method:'GET'},'Catalog comparison unavailable');
  },
  ruleCatalogDetail(id: number,application: string,environment: string): Promise<RuleCatalogDetail> {
    return call(`/rule-catalog/${id}?${new URLSearchParams({application_id:application,environment_id:environment})}`,{method:'GET'},'Rule telemetry unavailable');
  },
  exceptions(application: string,environment: string,after = ''): Promise<ExceptionInventoryPage> {
    return call(`/exceptions?${new URLSearchParams({application_id:application,environment_id:environment,after})}`,{method:'GET'},'Exception inventory unavailable');
  },
  exceptionLifecycle(action: 'revoke'|'cleanupExpired',request: ExceptionLifecycleRequest): Promise<EventRuleDraft> {
    return call(`/exceptions:${action}`,json('POST',request),'Unable to create exception draft');
  },
  savedSearches(application: string, environment: string, after = ''): Promise<components['schemas']['SavedSearchList']> {
    return call(`/saved-searches?${new URLSearchParams({application_id:application,environment_id:environment,after})}`,{method:'GET'},'Unable to load saved searches');
  },
  async savedSearch(id: string): Promise<SavedSearch> {
    return (await call<components['schemas']['SavedSearchReply']>(`/saved-searches/${encodeURIComponent(id)}`,{method:'GET'},'Saved search unavailable')).search;
  },
  async saveSearch(search: SavedSearchInput, request_id: string, create = true): Promise<SavedSearch> {
    const path = create ? '/saved-searches' : `/saved-searches/${encodeURIComponent(search.id ?? '')}`;
    return (await call<components['schemas']['SavedSearchReply']>(path,json(create?'POST':'PUT',{search,request_id}),'Unable to save search')).search;
  },
  searchSavedEvents(id: string, page_token = ''): Promise<SearchEventsResponse> {
    return call(`/saved-searches/${encodeURIComponent(id)}:search`,json('POST',{page_token}),'Saved search unavailable');
  },
  async eventCase(block: string): Promise<EventCase> {
    return (await call<components['schemas']['EventCaseReply']>(`/events/${encodeURIComponent(block)}:case`,{method:'GET'},'Case unavailable')).case;
  },
  async saveEventCase(value: EventCase, request_id: string): Promise<EventCase> {
    return (await call<components['schemas']['EventCaseReply']>(`/events/${encodeURIComponent(value.block_id)}:case`,json('POST',{case:value,request_id}),'Unable to save case')).case;
  },
  similarEvents(block: string): Promise<SearchEventsResponse> {
    return call(`/events/${encodeURIComponent(block)}:similar`,{method:'GET'},'Similar events unavailable');
  },
  proposeEventRule(block: string, request: EventRuleRequest): Promise<EventRuleDraft> {
    return call(`/events/${encodeURIComponent(block)}:propose-rule`,json('POST',request),'Unable to create draft');
  },
  async createEvidence(request: components['schemas']['EvidenceRequest']): Promise<EvidenceExport> {
    return (await call<components['schemas']['EvidenceReply']>('/evidence',json('POST',request),'Unable to queue export')).export;
  },
  evidenceList(application: string, environment: string): Promise<operations['listEvidence']['responses'][200]['content']['application/json']> {
    return call(`/evidence?${new URLSearchParams({application_id:application,environment_id:environment})}`,{method:'GET'},'Exports unavailable');
  },
  async evidence(id: string): Promise<EvidenceExport> {
    return (await call<components['schemas']['EvidenceReply']>(`/evidence/${encodeURIComponent(id)}`,{method:'GET'},'Export unavailable')).export;
  },
  downloadEvidence(id: string): Promise<Blob> {
    return call(`/evidence/${encodeURIComponent(id)}/download`,{method:'GET'},'Export unavailable',true);
  },
  localMfa(): Promise<MFAStatus> {return call('/auth/mfa',{method:'GET'},'MFA unavailable');},
  beginMfa(command: MFACommand): Promise<MFAEnrollment> {return call('/auth/mfa:begin',json('POST',command),'MFA enrollment failed');},
  confirmMfa(command: MFACommand): Promise<MFARecovery> {return call('/auth/mfa:confirm',json('POST',command),'MFA confirmation failed');},
  disableMfa(command: MFACommand): Promise<MFARecovery> {return call('/auth/mfa:disable',json('POST',command),'MFA change failed');},
  rotateMfaRecovery(command: MFACommand): Promise<MFARecovery> {return call('/auth/mfa:recovery',json('POST',command),'Recovery rotation failed');},
  ownSessions(): Promise<{sessions:OwnSession[]}> {return call('/auth/sessions',{method:'GET'},'Sessions unavailable');},
  revokeOwnSession(id:string,etag:string): Promise<void> {return call(`/auth/sessions/${encodeURIComponent(id)}:revoke`,json('POST',{etag} satisfies MFACommand),'Session revocation failed');},
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

  /** GET /v1/stats/geo: distinct events by country, cell, ASN or attack type (W18-G2-01) */
  getGeo(groupBy: GeoGroupBy, from: string, to: string, f: GeoFilters, limit = 20, signal?: AbortSignal): Promise<GeoResponse> {
    const q = geoQuery(f, { groupBy, from, to, limit: String(limit) });
    return call(`/stats/geo?${q}`, { method: 'GET', signal }, 'Failed to load map statistics');
  },

  /** GET /v1/stats/timeline: distinct events per step by action (W18-G2-01) */
  getTimeline(from: string, to: string, f: GeoFilters, signal?: AbortSignal): Promise<TimelineResponse> {
    return call(`/stats/timeline?${geoQuery(f, { from, to })}`, { method: 'GET', signal }, 'Failed to load the timeline');
  },

  /**
   * GET /v1/stats/geo:watch, read with fetch (the token goes in the
   * Authorization header). Calls onEvent for each event; reconnects when the
   * server ends the stream (every 15 minutes) or it breaks, after the
   * stream's retry delay; onState tells the page whether it is connected.
   * Returns when signal aborts; a 401 ends the session, 4xx stop.
   */
  async watchGeo(
    groupBy: GeoGroupBy,
    span: string,
    f: GeoFilters,
    onEvent: (e: SseEvent) => void,
    onState: (connected: boolean, error?: string) => void,
    signal: AbortSignal,
  ): Promise<void> {
    const q = geoQuery(f, { groupBy, window: span, limit: '20' });
    let retry = 3000;
    while (!signal.aborted) {
      try {
        const headers = new Headers({ Accept: 'text/event-stream' });
        const token = await handlers.token();
        if (token) headers.set('Authorization', `Bearer ${token}`);
        const res = await fetch(`${API_BASE}/stats/geo:watch?${q}`, { headers, signal });
        if (!res.ok || !res.body) {
          if (res.status === 401) handlers.unauthorized();
          let msg = `HTTP ${res.status}`;
          try {
            msg = ((await res.json()) as ErrorResponse).error || msg;
          } catch {
            // keep the status
          }
          // 503 (too many streams) and 5xx: try again; other 4xx: stop
          if (res.status >= 400 && res.status < 500 && res.status !== 429) {
            onState(false, msg);
            return;
          }
          throw new Error(msg);
        }
        onState(true);
        const parser = new SseParser();
        const reader = res.body.getReader();
        const dec = new TextDecoder();
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          for (const e of parser.push(dec.decode(value, { stream: true }))) onEvent(e);
        }
        retry = parser.retryMs;
        onState(false);
      } catch (e) {
        if (signal.aborted) return;
        onState(false, e instanceof Error ? e.message : String(e));
      }
      await new Promise<void>((done) => {
        const t = setTimeout(done, retry);
        signal.addEventListener('abort', () => {
          clearTimeout(t);
          done();
        }, { once: true });
      });
    }
  },

  /** POST /v1/auth/logout: ends a local session */
  logout(): Promise<void> {
    return call('/auth/logout', { method: 'POST' }, 'Failed to sign out');
  },

  listReleases(after=''):Promise<components['schemas']['ReleaseList']> {return call(`/releases?after=${encodeURIComponent(after)}`,{method:'GET'},'Failed to read releases');},
  getRelease(id:string):Promise<ReleaseDetail>{return call(`/releases/${encodeURIComponent(id)}`,{method:'GET'},'Failed to read release');},
  createRelease(request_id:string,source_release=''):Promise<components['schemas']['ReleaseResult']>{return call('/releases',{method:'POST',body:JSON.stringify({request_id,source_release})},'Failed to prepare release');},
  actRelease(id:string,action:'approve'|'reject'|'deploy',request:components['schemas']['ReleaseAction']):Promise<components['schemas']['ReleaseResult']>{return call(`/releases/${encodeURIComponent(id)}:${action}`,{method:'POST',body:JSON.stringify(request)},'Failed to change release');},
  systemHealth():Promise<HealthSnapshot>{return call('/health',{method:'GET'},'Health source unavailable');},
  listApplications(after = ''): Promise<components['schemas']['ApplicationList']> {
    return call(`/applications?after=${encodeURIComponent(after)}`, {method:'GET'}, 'Failed to read applications');
  },
  saveApplication(application:Application, create:boolean, request_id:string):Promise<components['schemas']['ApplicationResult']> {
    return call(`/applications${create ? '' : '/'+encodeURIComponent(application.id)}`,{method:create?'POST':'PUT',body:JSON.stringify({application,request_id})},'Failed to save application');
  },
  applicationOverview(id:string,from:string,to:string,environment_id=''):Promise<Overview> {
    return call(`/applications/${encodeURIComponent(id)}/overview?${new URLSearchParams({from,to,environment_id})}`,{method:'GET'},'Failed to read application statistics');
  },
  listApplicationBindings():Promise<components['schemas']['ApplicationBindings']> {
    return call('/application-role-bindings',{method:'GET'},'Failed to read bindings');
  },
  createApplicationBinding(binding:ApplicationBinding):Promise<components['schemas']['ApplicationBindingResult']> {
    return call('/application-role-bindings',{method:'POST',body:JSON.stringify({binding})},'Failed to bind role');
  },
  deleteApplicationBinding(id:number):Promise<void> {
    return call(`/application-role-bindings/${id}`,{method:'DELETE'},'Failed to revoke role');
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

  /** GET /v1/policyTemplates: the templates a new policy can start from (W20-S-01) */
  async listPolicyTemplates(): Promise<PolicyTemplate[]> {
    const r = await call<admin['schemas']['v1ListPolicyTemplatesResponse']>('/policyTemplates', { method: 'GET' }, 'Failed to list the policy templates');
    return r.templates ?? [];
  },

  /** POST /v1/policies?template=: a new policy, from a template or not (its first version is a DRAFT) */
  async createPolicy(id: string, name: string, template: string, spec?: PolicySpec): Promise<Policy> {
    const q = template ? `?template=${encodeURIComponent(template)}` : '';
    const r = await call<admin['schemas']['v1CreatePolicyResponse']>(`/policies${q}`, json('POST', { id, name, spec: spec ?? {} }), 'Failed to create the policy');
    return r.policy ?? {};
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
  async getOperation(id:string):Promise<Operation>{
    const r=await call<admin['schemas']['v1GetOperationResponse']>(`/operations/${encodeURIComponent(id)}`,{method:'GET'},'Failed to read pinned replay');
    if(!r.operation||r.operation.id!==id)throw new ApiError('Replay receipt mismatch',502);
    return r.operation;
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
    return (await apiClient.searchAuditLogs({limit})).entries ?? [];
  },
  async searchAuditLogs(query: AuditQuery, signal?: AbortSignal): Promise<ListAuditResponse> {
    const params = new URLSearchParams();
    for (const [key, value] of Object.entries(query)) if (value !== undefined && value !== '') params.set(key, String(value));
    return call<ListAuditResponse>(`/audit?${params}`, {method:'GET', signal}, 'Failed to search audit log');
  },
  /** GET /v1/service-accounts */
  async listServiceAccounts(): Promise<ServiceAccount[]> {
    const r = await call<{ service_accounts: ServiceAccount[] }>('/service-accounts', { method: 'GET' }, 'Failed to list service accounts');
    return r.service_accounts ?? [];
  },

  /** POST /v1/service-accounts */
  async createServiceAccount(sa: CreateServiceAccountRequest): Promise<ServiceAccount> {
    return call<ServiceAccount>('/service-accounts', json('POST', sa), 'Failed to create service account');
  },

  async deleteServiceAccount(id: string, etag: string, requestId: string): Promise<void> {
    await call<void>(`/service-accounts/${encodeURIComponent(id)}`, { method: 'DELETE',
      headers: { 'If-Match': etag, 'Idempotency-Key': requestId } }, 'Failed to delete service account');
  },

  async listServiceAccountTokens(saId: string): Promise<ServiceAccountToken[]> {
    const r = await call<components['schemas']['ServiceAccountTokenList']>(`/service-accounts/${encodeURIComponent(saId)}/tokens`, { method: 'GET' }, 'Failed to list tokens');
    return r.tokens ?? [];
  },

  async createServiceAccountToken(saId: string, req: CreateServiceAccountTokenRequest): Promise<CreateTokenResponse> {
    return call<CreateTokenResponse>(`/service-accounts/${encodeURIComponent(saId)}/tokens`, json('POST',req), 'Failed to create token');
  },

  async revokeServiceAccountToken(saId: string, tokenId: string, etag: string, requestId: string): Promise<void> {
    await call<void>(`/service-accounts/${encodeURIComponent(saId)}/tokens/${encodeURIComponent(tokenId)}`, { method: 'DELETE',
      headers: { 'If-Match': etag, 'Idempotency-Key': requestId } }, 'Failed to revoke token');
  },


};

export type ServiceAccount = components['schemas']['ServiceAccount'];
export type ServiceAccountToken = components['schemas']['ServiceAccountToken'];
export type CreateTokenResponse = components['schemas']['MachineTokenResponse'];
export type CreateServiceAccountRequest = components['schemas']['ServiceAccountCreateRequest'];
export type CreateServiceAccountTokenRequest = components['schemas']['MachineTokenRequest'];

export type AuditEntry = components['schemas']['AuditEntry'];
export type ListAuditResponse = components['schemas']['AuditListResponse'];
export type AuditQuery = NonNullable<operations['listAudit']['parameters']['query']>;
