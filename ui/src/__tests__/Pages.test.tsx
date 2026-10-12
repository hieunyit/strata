import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { StaticAuthProvider } from '../context/AuthContext';
import { PoliciesPage } from '../pages/PoliciesPage';
import { FleetPage } from '../pages/FleetPage';
import { apiClient, ApiError } from '../api/client';
import { parseRoute, href } from '../router';
import i18n from '../i18n';

beforeEach(() => {
  vi.restoreAllMocks();
  vi.spyOn(apiClient, 'getVersion').mockResolvedValue({ version: 'test', commit: '', api_version: 'v1' });
  void i18n.changeLanguage('en');
});

describe('routes', () => {
  it('parses and builds hash routes', () => {
    expect(parseRoute('')).toEqual({ page: 'events', blockId: undefined });
    expect(parseRoute('#/fleet')).toEqual({ page: 'fleet' });
    expect(parseRoute('#/policies')).toEqual({ page: 'policies' });
    expect(parseRoute('#/events/STR-AAAA-BBBB-CCCC-DDDD')).toEqual({ page: 'events', blockId: 'STR-AAAA-BBBB-CCCC-DDDD' });
    expect(href({ page: 'events', blockId: 'STR-A' })).toBe('#/events/STR-A');
  });
});

describe('policies page', () => {
  it('lists policies and shows the versions of one', async () => {
    vi.spyOn(apiClient, 'listPolicies').mockResolvedValue([
      { id: 'example-api', name: 'example-api', version: 3, spec: { mode: 'MODE_ENFORCE', oversize: 'OVERSIZE_BLOCK' }, created_by: 'lab-operator' },
      { id: 'example-web', name: 'example-web', version: 1, spec: { mode: 'MODE_SHADOW' } },
    ]);
    const versions = vi.spyOn(apiClient, 'listPolicyVersions').mockResolvedValue([
      { policy_id: 'example-api', version: 3, spec: { mode: 'MODE_ENFORCE' } },
      { policy_id: 'example-api', version: 2, spec: { mode: 'MODE_SHADOW' } },
    ]);
    render(<StaticAuthProvider roles={['viewer']}><PoliciesPage /></StaticAuthProvider>);
    const rows = await screen.findAllByTestId('policy-row');
    expect(rows).toHaveLength(2);
    expect(rows[0]).toHaveTextContent('Enforce');
    expect(rows[0]).toHaveTextContent('Block');
    fireEvent.click(rows[0]);
    await waitFor(() => expect(screen.getAllByTestId('policy-version-row')).toHaveLength(2));
    expect(versions).toHaveBeenCalledWith('example-api');
    // Read only: nothing to edit or deploy.
    expect(screen.queryByRole('button', { name: /deploy|edit/i })).not.toBeInTheDocument();
  });

  it('shows an empty state and API errors', async () => {
    vi.spyOn(apiClient, 'listPolicies').mockRejectedValue(new ApiError('permission denied', 403));
    render(<StaticAuthProvider roles={['viewer']}><PoliciesPage /></StaticAuthProvider>);
    expect(await screen.findByTestId('page-error')).toHaveTextContent('permission denied');
  });
});

describe('fleet page', () => {
  it('shows each node with its status and refreshes', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const nodes = vi.spyOn(apiClient, 'listNodes').mockResolvedValue([
      { id: 'node-a', hostname: 'edge-01', group_id: 'lab', online: true, proxy_version: '1.30.5' },
      { id: 'node-b', hostname: 'edge-02', group_id: 'lab', online: false },
      { id: 'node-c', hostname: 'edge-03', group_id: 'lab', online: false, revoked: true },
    ]);
    vi.spyOn(apiClient, 'listGroups').mockResolvedValue([{ id: 'lab', name: 'Lab' }]);
    vi.spyOn(apiClient, 'listRollouts').mockResolvedValue([{ id: '3', state: 'DONE' }]);
    render(<StaticAuthProvider roles={['viewer']}><FleetPage /></StaticAuthProvider>);
    const rows = await screen.findAllByTestId('node-row');
    expect(rows.map((r) => r.getAttribute('data-status'))).toEqual(['online', 'offline', 'revoked']);
    expect(screen.getByTestId('group')).toHaveTextContent('Lab');
    expect(rows[0]).toHaveTextContent('1.30.5');
    expect(screen.getByTestId('fleet-summary')).toHaveTextContent('1/3 nodes online');
    expect(screen.getByTestId('rollout-none')).toBeInTheDocument();
    const calls = nodes.mock.calls.length;
    await vi.advanceTimersByTimeAsync(3100);
    expect(nodes.mock.calls.length).toBeGreaterThan(calls);
    vi.useRealTimers();
  });
});

describe('CSV export is an operator+ action (W08-F-01)', () => {
  it('policies: every role can export', async () => {
    vi.spyOn(apiClient, 'listPolicies').mockResolvedValue([
      { id: 'example-api', name: 'example-api', version: 3, spec: { mode: 'MODE_ENFORCE', oversize: 'OVERSIZE_BLOCK' }, created_by: 'lab-operator' },
    ]);
    const { unmount } = render(<StaticAuthProvider roles={['operator']}><PoliciesPage /></StaticAuthProvider>);
    await screen.findAllByTestId('policy-row');
    expect(screen.getByTestId('export-csv-btn')).toBeInTheDocument();
    unmount();

    render(<StaticAuthProvider roles={['viewer']}><PoliciesPage /></StaticAuthProvider>);
    await screen.findAllByTestId('policy-row');
    expect(screen.getByTestId('export-csv-btn')).toBeInTheDocument();
  });

  it('fleet: every role can export', async () => {
    const nodes = [{ id: 'node-a', hostname: 'edge-01', group_id: 'lab', online: true, proxy_version: '1.30.5' }];
    vi.spyOn(apiClient, 'listNodes').mockResolvedValue(nodes);
    vi.spyOn(apiClient, 'listGroups').mockResolvedValue([{ id: 'lab', name: 'Lab' }]);
    vi.spyOn(apiClient, 'listRollouts').mockResolvedValue([]);
    const { unmount } = render(<StaticAuthProvider roles={['operator']}><FleetPage /></StaticAuthProvider>);
    await screen.findAllByTestId('node-row');
    expect(screen.getByTestId('export-csv-btn')).toBeInTheDocument();
    unmount();

    render(<StaticAuthProvider roles={['viewer']}><FleetPage /></StaticAuthProvider>);
    await screen.findAllByTestId('node-row');
    expect(screen.getByTestId('export-csv-btn')).toBeInTheDocument();
  });
});
