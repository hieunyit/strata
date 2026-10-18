import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { apiClient, setAuthHandlers } from '../api/client';

const fetchMock = vi.fn();
const op = { id: 'op-example', kind: 'REPLAY', policy_id: 'example-api', version: 2, state: 'PENDING' };
const answer = (body: unknown, status = 200) => fetchMock.mockResolvedValueOnce(new Response(JSON.stringify(body), { status }));
beforeEach(() => {
  fetchMock.mockReset(); vi.stubGlobal('fetch', fetchMock);
  setAuthHandlers({ token: async () => 'lab-token', unauthorized: vi.fn() });
});
afterEach(() => { vi.unstubAllGlobals(); setAuthHandlers({ token: async () => undefined, unauthorized: () => {} }); });

describe('policy review client', () => {
  it('uses the global submitted queue and passes cancellation/authentication', async () => {
    const controller = new AbortController();
    answer({ versions: [{ policy_id: 'example-api', version: 2, state: 'SUBMITTED' }] });
    expect(await apiClient.listSubmittedPolicyVersions(controller.signal)).toHaveLength(1);
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe('/v1/policies/-/versions?state=SUBMITTED');
    expect(init.signal).toBe(controller.signal);
    expect(init.headers.get('Authorization')).toBe('Bearer lab-token');
  });
  it('never submits or decides version zero/latest or an invalid version', async () => {
    for (const v of [0, -1, NaN, 1.5, 0x100000000]) {
      await expect(apiClient.submitPolicy('example-api', v)).rejects.toMatchObject({ code: 400 });
      await expect(apiClient.approvePolicy('example-api', v)).rejects.toMatchObject({ code: 400 });
      await expect(apiClient.rejectPolicy('example-api', v, 'reason')).rejects.toMatchObject({ code: 400 });
      await expect(apiClient.replayPolicy('example-api', v)).rejects.toMatchObject({ code: 400 });
    }
    expect(fetchMock).not.toHaveBeenCalled();
  });
  it('requires a rejection reason and checks each decision receipt', async () => {
    await expect(apiClient.rejectPolicy('example-api', 2, '  ')).rejects.toMatchObject({ code: 400 });
    expect(fetchMock).not.toHaveBeenCalled();
    for (const [action, state] of [['submitPolicy', 'SUBMITTED'], ['approvePolicy', 'APPROVED'], ['rejectPolicy', 'REJECTED']] as const) {
      answer({ version: { policy_id: 'example-api', version: 2, state } });
      await expect(apiClient[action]('example-api', 2, 'reason')).resolves.toMatchObject({ version: 2, state });
    }
    answer({ version: { policy_id: 'example-api', version: 3, state: 'APPROVED' } });
    await expect(apiClient.approvePolicy('example-api', 2)).rejects.toMatchObject({ code: 502 });
    answer({}); await expect(apiClient.submitPolicy('example-api', 2)).rejects.toMatchObject({ code: 502 });
    const [, init] = fetchMock.mock.calls[0]; expect(JSON.parse(init.body)).toEqual({ version: 2 });
  });
  it('sends the inspected report ID without retrying unpinned on conflict', async () => {
    answer({ message: 'replay changed' }, 400);
    await expect(apiClient.approvePolicy('example-api', 2, 'reviewed', 'op-viewed')).rejects.toMatchObject({ code: 400 });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(JSON.parse(fetchMock.mock.calls[0][1].body)).toEqual({ version: 2, comment: 'reviewed', expected_replay_id: 'op-viewed' });
  });
  it('requires a pinned approval receipt to retain the same replay proof', async () => {
    answer({ version: { policy_id: 'example-api', version: 2, state: 'APPROVED', approved_replay_id: 'op-other' } });
    await expect(apiClient.approvePolicy('example-api', 2, '', 'op-viewed')).rejects.toMatchObject({ code: 502 });
    answer({ version: { policy_id: 'example-api', version: 2, state: 'APPROVED', approved_replay_id: 'op-viewed' } });
    expect((await apiClient.approvePolicy('example-api', 2, '', 'op-viewed')).approved_replay_id).toBe('op-viewed');
  });
  it('distinguishes missing replay from forbidden or unavailable replay', async () => {
    answer({}, 404); expect(await apiClient.getVersionReplay('example-api', 2)).toBeUndefined();
    for (const status of [403, 503]) {
      answer({}, status); await expect(apiClient.getVersionReplay('example-api', 2)).rejects.toMatchObject({ code: status });
    }
  });
  it('binds operations to the inspected policy/version and requires a DONE report', async () => {
    answer({ operation: op }); expect(await apiClient.replayPolicy('example-api', 2)).toEqual(op);
    for (const changed of [{ policy_id: 'other' }, { version: 3 }, { state: 'DONE', done: true }, { state: 'INVENTED' }]) {
      answer({ operation: { ...op, ...changed } });
      await expect(apiClient.getVersionReplay('example-api', 2)).rejects.toMatchObject({ code: 502 });
    }
    answer({ operation: { ...op, state: 'DONE', done: true, replay: { samples: '18446744073709551615' } } });
    expect((await apiClient.getVersionReplay('example-api', 2))?.replay?.samples).toBe('18446744073709551615');
  });
  it('rejects malformed queue rows without converting them to an empty queue', async () => {
    answer({ versions: [{ policy_id: 'example-api', version: 2, state: 'APPROVED' }] });
    await expect(apiClient.listSubmittedPolicyVersions()).rejects.toMatchObject({ code: 502 });
    for (const row of [null, { policy_id: 'example-api', version: -1, state: 'SUBMITTED' }]) {
      answer({ versions: [row] }); await expect(apiClient.listSubmittedPolicyVersions()).rejects.toMatchObject({ code: 502 });
    }
    answer({}); expect(await apiClient.listSubmittedPolicyVersions()).toEqual([]);
  });
});
