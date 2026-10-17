import { beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { ExceptionDraft } from '../components/events/ExceptionDraft';
import { ApiError, Event, ExceptionDraftResponse, GetEventResponse, apiClient } from '../api/client';
import { StaticAuthProvider, UserRole } from '../context/AuthContext';
import i18n from '../i18n';

const event: Event = {
  block_id: 'STR-8F3K-Q2VD-7XNM-A1PC', timestamp: '2026-10-17T00:00:00Z', node_id: 'example-node', connector_type: 'nginx', policy_id: 'example-api', policy_version: 3, client_ip: '198.51.100.42',
  http_method: 'POST', http_host: 'api.example.test', http_path: '/v1/search', action: 'block', status_code: 403,
  violations: [{ rule_id: 700011, layer: 'sqli', field: 'ARGS:Name', snippet: 'example' }],
};
const rules = { '700011': { name: 'example SQLi', layer: 'managed' } };
const receipt: ExceptionDraftResponse = { state: 'DRAFT', policy_id: 'resource-1', policy_version: 4, etag: 'v4', replay_url: '/v1/policies/resource-1/versions/4/replay',
  exception: { id: 'exc-example', rule_id: 700011, method: 'POST', host: 'api.example.test', path: '/v1/search', field: 'ARGS:Name', reason: 'legitimate query', expires_unix_ms: Date.now() + 3600000 } };

beforeEach(() => {
  vi.restoreAllMocks();
  void i18n.changeLanguage('en');
  vi.spyOn(apiClient, 'listPolicies').mockResolvedValue([{ id: 'resource-1', name: 'example-api', etag: 'v3', version: 3 }]);
  vi.spyOn(apiClient, 'createExceptionFromBlock').mockResolvedValue(receipt);
});
const setup = (roles: UserRole[] = ['operator'], ev = event, catalog: GetEventResponse['rules'] = rules) => render(
  <StaticAuthProvider roles={roles}><ExceptionDraft event={ev} rules={catalog} /></StaticAuthProvider>,
);
async function open() {
  fireEvent.click(screen.getByRole('button', { name: 'Create exception' }));
  await waitFor(() => expect(screen.queryByText('Reading the current policy…')).not.toBeInTheDocument());
  return screen.getByLabelText('Reason');
}
const send = () => fireEvent.click(screen.getByRole('button', { name: 'Create draft' }));

describe('exception draft from a Block ID', () => {
  it('hides writes for viewer/approver and non-block events without reading policies', () => {
    for (const role of ['viewer', 'approver'] as UserRole[]) {
      setup([role]); expect(screen.queryByRole('button')).not.toBeInTheDocument(); cleanup();
    }
    setup(['operator'], { ...event, action: 'shadow' });
    expect(screen.queryByRole('button')).not.toBeInTheDocument();
    expect(apiClient.listPolicies).not.toHaveBeenCalled();
  });

  it('requires an unambiguous managed rule and exact field', () => {
    for (const field of ['ARGS:Name|base64', 'ARGS:*', 'REQUEST_BODY']) {
      setup(['admin'], { ...event, violations: [{ ...event.violations![0], field }] });
      expect(screen.getByRole('button', { name: 'Create exception' })).toBeDisabled(); cleanup();
    }
    setup(['operator'], event, { '700011': { name: 'core rule', layer: 'protocol' } });
    expect(screen.getByRole('button', { name: 'Create exception' })).toBeDisabled();
  });

  it('creates only a scoped draft with the current name-matched etag and mandatory TTL/reason', async () => {
    setup(['admin']); const reason = await open();
    expect(screen.getByTestId('exception-route')).toHaveTextContent('POST api.example.test/v1/search');
    expect(screen.getByRole('button', { name: 'Create draft' })).toBeDisabled();
    fireEvent.change(reason, { target: { value: ' legitimate query ' } }); send();
    await screen.findByTestId('exception-created');
    expect(apiClient.createExceptionFromBlock).toHaveBeenCalledTimes(1);
    expect(apiClient.createExceptionFromBlock).toHaveBeenCalledWith({ block_id: event.block_id, rule_id: 700011, field: 'ARGS:Name', reason: 'legitimate query', ttl_seconds: 3600, etag: 'v3', request_id: expect.any(String) });
    expect(screen.getByText('The exception takes effect only after replay, independent approval and deployment.')).toBeInTheDocument();
  });

  it('retains exactly the command and request ID after an uncertain write and blocks duplicate clicks', async () => {
    let fail!: (e: Error) => void;
    vi.mocked(apiClient.createExceptionFromBlock).mockImplementationOnce(() => new Promise((_, reject) => { fail = reject; }));
    setup(); fireEvent.change(await open(), { target: { value: 'legitimate query' } }); send();
    expect(screen.getByLabelText('Reason')).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Creating draft…' })).toBeDisabled();
    fireEvent.submit(screen.getByRole('button', { name: 'Creating draft…' }).closest('form')!);
    expect(apiClient.createExceptionFromBlock).toHaveBeenCalledTimes(1);
    fail(new ApiError('response lost', 503));
    const retry = await screen.findByRole('button', { name: 'Retry the same request' });
    expect(screen.getByLabelText('Duration')).toBeDisabled();
    fireEvent.click(retry); await screen.findByTestId('exception-created');
    expect(apiClient.createExceptionFromBlock).toHaveBeenCalledTimes(2);
    expect(vi.mocked(apiClient.createExceptionFromBlock).mock.calls[1][0]).toEqual(vi.mocked(apiClient.createExceptionFromBlock).mock.calls[0][0]);
  });

  it('requires explicit policy reload on conflict and never silently rebases a write', async () => {
    vi.mocked(apiClient.createExceptionFromBlock).mockRejectedValueOnce(new ApiError('stale', 409));
    setup(); fireEvent.change(await open(), { target: { value: 'legitimate query' } }); send();
    await screen.findByRole('button', { name: 'Reload policy' });
    expect(screen.getByRole('button', { name: 'Create draft' })).toBeDisabled();
    expect(apiClient.listPolicies).toHaveBeenCalledTimes(1);
    vi.mocked(apiClient.listPolicies).mockResolvedValueOnce([{ id: 'resource-1', name: 'example-api', etag: 'new-etag' }]);
    fireEvent.click(screen.getByRole('button', { name: 'Reload policy' }));
    await waitFor(() => expect(screen.getByRole('button', { name: 'Create draft' })).toBeEnabled());
    send(); await screen.findByTestId('exception-created');
    expect(vi.mocked(apiClient.createExceptionFromBlock).mock.calls[1][0].etag).toBe('new-etag');
    expect(vi.mocked(apiClient.createExceptionFromBlock).mock.calls[1][0].request_id).not.toBe(vi.mocked(apiClient.createExceptionFromBlock).mock.calls[0][0].request_id);
  });

  it('rejects an unmatched policy, long UTF-8 reason, and a malformed success receipt', async () => {
    vi.mocked(apiClient.listPolicies).mockResolvedValueOnce([{ id: 'other-id', name: 'other-policy', etag: 'wrong' }]);
    setup(); await open(); expect(screen.getByRole('button', { name: 'Create draft' })).toBeDisabled(); cleanup();
    setup(); const reason = await open(); fireEvent.change(reason, { target: { value: '界'.repeat(200) } });
    expect(screen.getByRole('button', { name: 'Create draft' })).toBeDisabled();
    fireEvent.change(reason, { target: { value: 'legitimate query' } });
    vi.mocked(apiClient.createExceptionFromBlock).mockResolvedValueOnce({ ...receipt, state: 'DEPLOYED' } as unknown as ExceptionDraftResponse);
    send(); await screen.findByRole('button', { name: 'Retry the same request' });
    expect(screen.queryByTestId('exception-created')).not.toBeInTheDocument();
  });
  it('keeps exact selected header scope and refuses writes after permission is lost', async () => {
    const second = { rule_id: 700012, layer: 'xss', field: 'REQUEST_HEADERS:X-Example-Text', snippet: 'example' };
    setup(['operator'], { ...event, violations: [...event.violations!, second] }, { ...rules, '700012': { name: 'example XSS', layer: 'managed' } });
    fireEvent.change(await open(), { target: { value: 'legitimate header' } });
    fireEvent.change(screen.getByLabelText('Rule and field'), { target: { value: '1' } });
    fireEvent.change(screen.getByLabelText('Duration'), { target: { value: '86400' } });
    vi.mocked(apiClient.createExceptionFromBlock).mockRejectedValueOnce(new ApiError('denied', 403));
    send();
    await screen.findByText('You no longer have permission to create an exception.');
    expect(screen.getByRole('button', { name: 'Create draft' })).toBeDisabled();
    expect(apiClient.createExceptionFromBlock).toHaveBeenCalledWith(expect.objectContaining({ rule_id: 700012, field: 'REQUEST_HEADERS:X-Example-Text', ttl_seconds: 86400 }));
  });

});
