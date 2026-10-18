import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { StaticAuthProvider } from '../context/AuthContext';
import { RuleStagingNotifications } from '../components/layout/RuleStagingNotifications';
import { apiClient, RuleStagingNotice, RuleStagingNoticePage } from '../api/client';
import i18n from '../i18n';

const notice: RuleStagingNotice = { id: 'example-action', policy_id: 'example-api', policy_name: 'example-api', policy_version: 1,
  rule_id: 700011, source_bundle: '1', bundle_version: '2', matches: '18446744073709551615', reports: '5',
  window_from: '2026-10-17T00:00:00Z', window_to: '2026-10-17T00:05:00Z', created_at: '2026-10-17T00:05:01Z',
  rollout_id: '', rollout_state: 'PENDING' };
const page = { notices: [notice], next_cursor: '' };
const show = (roles: ('viewer' | 'operator' | 'approver' | 'admin')[] = ['approver'], username = 'reviewer') =>
  render(<StaticAuthProvider roles={roles} username={username}><RuleStagingNotifications /></StaticAuthProvider>);

beforeEach(() => { vi.restoreAllMocks(); localStorage.clear(); void i18n.changeLanguage('en'); });

describe('durable staging notifications', () => {
  it('only requests reviewer notices for approver/admin', async () => {
    const read = vi.spyOn(apiClient, 'listRuleStagingNotices').mockResolvedValue(page);
    for (const role of ['viewer', 'operator'] as const) {
      const view = show([role]);
      expect(screen.queryByTestId('staging-notices-toggle')).not.toBeInTheDocument();
      view.unmount();
    }
    expect(read).not.toHaveBeenCalled();
    for (const role of ['approver', 'admin'] as const) {
      const view = show([role]);
      expect(await screen.findByTestId('staging-unread')).toBeInTheDocument();
      view.unmount();
    }
    expect(read).toHaveBeenCalledTimes(2);
  });

  it('shows exact evidence and publication state, with event review and browser-local read status', async () => {
    vi.spyOn(apiClient, 'listRuleStagingNotices').mockResolvedValue(page);
    const view = show();
    await screen.findByTestId('staging-unread');
    fireEvent.click(screen.getByTestId('staging-notices-toggle'));
    expect(await screen.findByText(/5 reported FP \/ 18446744073709551615/)).toBeInTheDocument();
    expect(screen.getByText('Rollout: Waiting to start')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Review events' })).toHaveAttribute('href', '#/events?rule_id=700011&policy_id=example-api&range=24h');
    fireEvent.click(screen.getByRole('button', { name: 'Mark read in this browser' }));
    expect(screen.queryByTestId('staging-unread')).not.toBeInTheDocument();
    view.unmount();
    const same = show();
    await waitFor(() => expect(apiClient.listRuleStagingNotices).toHaveBeenCalledTimes(2));
    expect(screen.queryByTestId('staging-unread')).not.toBeInTheDocument();
    same.unmount();
    show(['approver'], 'another-reviewer');
    expect(await screen.findByTestId('staging-unread')).toBeInTheDocument();
  });

  it('pages history and returns to latest without changing policy state', async () => {
    const older = { ...notice, id: 'older-action', rule_id: 700012, rollout_state: 'PAUSED' as const };
    const read = vi.spyOn(apiClient, 'listRuleStagingNotices').mockImplementation(async (cursor) => cursor ? { notices: [older], next_cursor: '' } : { notices: [notice], next_cursor: 'older-cursor' });
    show(); await screen.findByTestId('staging-unread');
    fireEvent.click(screen.getByTestId('staging-notices-toggle'));
    fireEvent.click(await screen.findByRole('button', { name: 'Older' }));
    expect(await screen.findByText('Rule 700012 · example-api v1')).toBeInTheDocument();
    expect(read).toHaveBeenLastCalledWith('older-cursor', expect.any(AbortSignal));
    fireEvent.click(screen.getByRole('button', { name: 'Latest' }));
    expect(await screen.findByText('Rule 700011 · example-api v1')).toBeInTheDocument();
    fireEvent.keyDown(document, { key: 'Escape' });
    expect(screen.queryByRole('region')).not.toBeInTheDocument();
    expect(screen.getByTestId('staging-notices-toggle')).toHaveFocus();
  });

  it('shows an unavailable channel rather than an empty history or backend details', async () => {
    vi.spyOn(apiClient, 'listRuleStagingNotices').mockRejectedValue(new Error('private-fixture-detail'));
    show();
    fireEvent.click(screen.getByTestId('staging-notices-toggle'));
    expect(await screen.findByRole('alert')).toHaveTextContent('Staging notices are unavailable');
    expect(screen.queryByText('No recorded staging changes.')).not.toBeInTheDocument();
    expect(screen.queryByText('private-fixture-detail')).not.toBeInTheDocument();
  });

  it('rejects a malformed page without corrupting visible history', async () => {
    vi.spyOn(apiClient, 'listRuleStagingNotices').mockResolvedValue({ notices: null } as unknown as RuleStagingNoticePage);
    show();
    fireEvent.click(screen.getByTestId('staging-notices-toggle'));
    expect(await screen.findByRole('alert')).toHaveTextContent('Staging notices are unavailable');
    expect(screen.queryByText('No recorded staging changes.')).not.toBeInTheDocument();
  });

  it('polls without overlap and aborts/unsubscribes on unmount', async () => {
    vi.useFakeTimers();
    try {
      let finish!: (value: RuleStagingNoticePage) => void;
      const pending = new Promise<RuleStagingNoticePage>((resolve) => { finish = resolve; });
      const read = vi.spyOn(apiClient, 'listRuleStagingNotices').mockReturnValueOnce(pending).mockResolvedValue(page);
      let view: ReturnType<typeof render>;
      await act(async () => { view = show(); });
      expect(read).toHaveBeenCalledTimes(1);
      await act(async () => { await vi.advanceTimersByTimeAsync(15_000); });
      expect(read).toHaveBeenCalledTimes(1); // pending request prevents overlap
      await act(async () => { finish(page); });
      await act(async () => { await vi.advanceTimersByTimeAsync(15_000); });
      expect(read).toHaveBeenCalledTimes(2);
      const signal = read.mock.calls[1][1];
      view!.unmount();
      expect(signal?.aborted).toBe(true);
      await act(async () => { await vi.advanceTimersByTimeAsync(30_000); });
      expect(read).toHaveBeenCalledTimes(2);
    } finally { vi.useRealTimers(); }
  });

  it('renders Vietnamese reviewer guidance', async () => {
    await i18n.changeLanguage('vi');
    vi.spyOn(apiClient, 'listRuleStagingNotices').mockResolvedValue(page);
    show(); await screen.findByTestId('staging-unread');
    fireEvent.click(screen.getByTestId('staging-notices-toggle'));
    expect(await screen.findByText('Rollout: Chờ bắt đầu')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Xem xét sự kiện' })).toBeInTheDocument();
  });
});
