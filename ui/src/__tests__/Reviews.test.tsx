import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ReviewsPage } from '../pages/ReviewsPage';
import { apiClient, PolicyVersion } from '../api/client';
import { StaticAuthProvider } from '../context/AuthContext';
import i18n from '../i18n';

vi.mock('../pages/PageShell', () => ({ PageShell: ({ children }: { children: React.ReactNode }) => <main>{children}</main> }));
const version = (v = 4, state: PolicyVersion['state'] = 'SUBMITTED', id = 'example-api'): PolicyVersion => ({ policy_id: id, version: v, state, spec: { mode: 'MODE_ENFORCE' }, created_by: 'writer', submitted_by: 'writer' });
const show = () => render(<StaticAuthProvider roles={['viewer']}><ReviewsPage /></StaticAuthProvider>);
beforeEach(async () => {
  vi.restoreAllMocks(); await i18n.changeLanguage('en');
  vi.spyOn(apiClient, 'listSubmittedPolicyVersions').mockResolvedValue([version()]);
  vi.spyOn(apiClient, 'listPolicyVersions').mockResolvedValue([version(), version(3, 'DRAFT'), version(2, 'APPROVED')]);
  vi.spyOn(apiClient, 'getVersionReplay').mockResolvedValue(undefined);
});
describe('review queue reads', () => {
  it('pages 50 rows and loads replay only for the inspected version', async () => {
    vi.mocked(apiClient.listSubmittedPolicyVersions).mockResolvedValue(Array.from({ length: 51 }, (_, i) => version(4, 'SUBMITTED', `example-${i}`)));
    vi.mocked(apiClient.listPolicyVersions).mockResolvedValue([version(4, 'SUBMITTED', 'example-50')]);
    show(); await screen.findByTestId('reviews-table');
    expect(screen.getAllByTestId('review-row')).toHaveLength(50);
    expect(apiClient.getVersionReplay).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button', { name: 'Next' }));
    expect(screen.getAllByTestId('review-row')).toHaveLength(1);
    fireEvent.click(screen.getByRole('button', { name: 'Inspect version' }));
    await screen.findByText('No replay has been queued for this version.');
    expect(apiClient.getVersionReplay).toHaveBeenCalledTimes(1);
    expect(apiClient.getVersionReplay).toHaveBeenCalledWith('example-50', 4, expect.any(AbortSignal));
  });
  it('compares exact candidate against approved version, preserves selection across locale', async () => {
    show(); fireEvent.click(await screen.findByRole('button', { name: 'Inspect version' }));
    const from = await screen.findByTestId('diff-from'), to = screen.getByTestId('diff-to');
    expect(from).toHaveValue('2'); expect(to).toHaveValue('4'); expect(from).toBeDisabled(); expect(to).toBeDisabled();
    await act(async () => { await i18n.changeLanguage('vi'); });
    expect(screen.getByTestId('diff-to')).toHaveValue('4');
    expect(apiClient.listPolicyVersions).toHaveBeenCalledTimes(1); expect(apiClient.getVersionReplay).toHaveBeenCalledTimes(1);
    expect(screen.getByText('Version này chưa có replay được xếp hàng.')).toBeInTheDocument();
  });
  it('does not present a failed queue read as an empty queue', async () => {
    vi.mocked(apiClient.listSubmittedPolicyVersions).mockRejectedValue(new Error('private detail'));
    show(); expect(await screen.findByRole('alert')).toHaveTextContent('Review data is unavailable');
    expect(screen.queryByText('No versions are awaiting approval.')).not.toBeInTheDocument();
    expect(screen.queryByText('private detail')).not.toBeInTheDocument();
  });
  it('refuses mismatched version data and shows first approval without a fabricated baseline', async () => {
    vi.mocked(apiClient.listPolicyVersions).mockResolvedValue([version(9)]);
    show(); fireEvent.click(await screen.findByRole('button', { name: 'Inspect version' }));
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('Review data is unavailable'));
    expect(screen.queryByTestId('replay-summary')).not.toBeInTheDocument();
    vi.mocked(apiClient.listPolicyVersions).mockResolvedValue([version()]);
    fireEvent.click(screen.getAllByRole('button', { name: 'Reload review' })[1]);
    expect(await screen.findByText(/No other approved version exists/)).toBeInTheDocument();
    expect(screen.queryByTestId('policy-diff')).not.toBeInTheDocument();
  });
});
