import { beforeEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { FalsePositive } from '../components/events/FalsePositive';
import { ApiError, Event, MarkFalsePositiveResponse, apiClient } from '../api/client';
import { StaticAuthProvider, UserRole } from '../context/AuthContext';
import i18n from '../i18n';

const event: Event = { block_id: 'STR-0000-0000-0000-0001', timestamp: '2026-10-18T00:00:00Z', node_id: 'example-node', connector_type: 'nginx', policy_id: 'example-api', policy_version: 1, client_ip: '198.51.100.42', http_method: 'GET', http_host: 'api.example.test', http_path: '/search', action: 'block', status_code: 403 };
const receipt: MarkFalsePositiveResponse = { block_id: event.block_id, false_positive: true, reason: 'example legitimate request', marked_by: 'example-operator', marked_at: '2026-10-18T00:00:00Z', etag: 'annotation-1' };
const reload = vi.fn();
beforeEach(() => { vi.restoreAllMocks(); reload.mockReset(); void i18n.changeLanguage('en'); vi.spyOn(apiClient, 'markFalsePositive').mockResolvedValue(receipt); });
const setup = (roles: UserRole[] = ['operator'], ev = event) => render(<StaticAuthProvider roles={roles}><FalsePositive event={ev} onReload={reload} /></StaticAuthProvider>);
const open = () => { fireEvent.click(screen.getByRole('button', { name: 'Mark false positive' })); return screen.getByLabelText('Classification reason'); };
const send = () => fireEvent.click(screen.getByRole('button', { name: 'Save classification' }));

describe('durable event classification', () => {
  it('hides writes for viewer/approver and preserves existing classification on read', () => {
    for (const role of ['viewer', 'approver'] as UserRole[]) { setup([role]); expect(screen.queryByRole('button')).not.toBeInTheDocument(); cleanup(); }
    setup(['viewer'], { ...event, false_positive: true, false_positive_reason: 'legitimate', false_positive_by: 'example-operator', false_positive_at: receipt.marked_at });
    expect(screen.getByTestId('false-positive-saved')).toHaveTextContent('legitimate');
    expect(apiClient.markFalsePositive).not.toHaveBeenCalled();
  });
  it('saves a bounded reason with request ID and current annotation etag', async () => {
    setup(['admin'], { ...event, annotation_etag: 'read-etag' }); const input = open();
    expect(input).toHaveFocus(); expect(screen.getByRole('button', { name: 'Save classification' })).toBeDisabled();
    fireEvent.change(input, { target: { value: '界'.repeat(200) } });
    expect(screen.getByRole('button', { name: 'Save classification' })).toBeDisabled();
    fireEvent.change(input, { target: { value: ' example legitimate request ' } }); send();
    expect(await screen.findByTestId('false-positive-saved')).toHaveTextContent('example-operator');
    expect(apiClient.markFalsePositive).toHaveBeenCalledWith(event.block_id, { reason: receipt.reason, etag: 'read-etag', request_id: expect.any(String) });
    await act(async () => { await i18n.changeLanguage('vi'); });
    expect(screen.getByTestId('false-positive-saved')).toHaveTextContent('Đã đánh dấu false positive');
  });
  it('keeps the identical command for ambiguous retry and prevents concurrent writes', async () => {
    let reject!: (cause: Error) => void;
    vi.mocked(apiClient.markFalsePositive).mockImplementationOnce(() => new Promise((_, fail) => { reject = fail; }));
    setup(); fireEvent.change(open(), { target: { value: receipt.reason } }); send();
    fireEvent.submit(screen.getByRole('button', { name: 'Saving classification…' }).closest('form')!);
    expect(apiClient.markFalsePositive).toHaveBeenCalledTimes(1);
    await act(async () => reject(new ApiError('response lost', 503)));
    expect(screen.getByLabelText('Classification reason')).toBeDisabled(); expect(screen.getByRole('button', { name: 'Cancel' })).toBeDisabled();
    fireEvent.click(screen.getByRole('button', { name: 'Retry the same classification' })); await screen.findByTestId('false-positive-saved');
    expect(vi.mocked(apiClient.markFalsePositive).mock.calls[1]).toEqual(vi.mocked(apiClient.markFalsePositive).mock.calls[0]);
  });
  it('requires explicit reload on etag conflict and stops after a 403', async () => {
    for (const status of [409, 403]) {
      vi.mocked(apiClient.markFalsePositive).mockRejectedValueOnce(new ApiError('refused', status));
      setup(); fireEvent.change(open(), { target: { value: receipt.reason } }); send();
      await screen.findByRole('alert'); expect(screen.getByRole('button', { name: 'Save classification' })).toBeDisabled();
      if (status === 409) { fireEvent.click(screen.getByRole('button', { name: 'Reload event' })); expect(reload).toHaveBeenCalledTimes(1); }
      cleanup();
    }
  });
  it('does not confirm a malformed or wrong-event success receipt', async () => {
    vi.mocked(apiClient.markFalsePositive).mockResolvedValueOnce({ ...receipt, block_id: 'STR-0000-0000-0000-0002' });
    setup(); fireEvent.change(open(), { target: { value: receipt.reason } }); send();
    await screen.findByRole('button', { name: 'Retry the same classification' });
    expect(screen.queryByTestId('false-positive-saved')).not.toBeInTheDocument();
  });
  it('uses the generated operation contract and encoded API path', async () => {
    vi.mocked(apiClient.markFalsePositive).mockRestore();
    const fetcher = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify(receipt), { status: 200 }));
    const command = { reason: receipt.reason, etag: 'read-etag', request_id: 'example-request' };
    expect(await apiClient.markFalsePositive(event.block_id, command)).toEqual(receipt);
    expect(fetcher).toHaveBeenCalledWith(`/v1/events/${event.block_id}:markFalsePositive`, expect.objectContaining({ method: 'POST', body: JSON.stringify(command) }));
  });
});
