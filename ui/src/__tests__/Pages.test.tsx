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
    render(<StaticAuthProvider roles={['viewer']}><FleetPage /></StaticAuthProvider>);
    const rows = await screen.findAllByTestId('node-row');
    expect(rows.map((r) => r.getAttribute('data-status'))).toEqual(['online', 'offline', 'revoked']);
    expect(rows[0]).toHaveTextContent('Lab');
    expect(screen.getByTestId('fleet-summary')).toHaveTextContent('1/3 nodes online');
    const calls = nodes.mock.calls.length;
    await vi.advanceTimersByTimeAsync(5100);
    expect(nodes.mock.calls.length).toBeGreaterThan(calls);
    vi.useRealTimers();
  });
});
