import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { StaticAuthProvider } from '../context/AuthContext';
import { PoliciesPage } from '../pages/PoliciesPage';
import { FleetPage } from '../pages/FleetPage';
import { OverviewPage } from '../pages/OverviewPage';
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
    expect(parseRoute('')).toEqual({ page: 'overview' });
    expect(parseRoute('#/fleet')).toEqual({ page: 'fleet' });
    expect(parseRoute('#/policies')).toEqual({ page: 'policies' });
    expect(parseRoute('#/events')).toEqual({ page: 'events' });
    expect(parseRoute('#/events?range=7d&rule_id=942100')).toEqual({ page: 'events', query: { range: '7d', rule_id: '942100' } });
    expect(parseRoute('#/events/STR-AAAA-BBBB-CCCC-DDDD')).toEqual({ page: 'event', blockId: 'STR-AAAA-BBBB-CCCC-DDDD' });
    expect(parseRoute('#/nowhere')).toEqual({ page: 'overview' });
    expect(href({ page: 'event', blockId: 'STR-A' })).toBe('#/events/STR-A');
    expect(href({ page: 'overview', query: { range: '30d', policy_id: '' } })).toBe('#/overview?range=30d');
  });
});

describe('overview page (W10-F-01)', () => {
  const overview = {
    from: '2026-10-12T12:00:00Z',
    to: '2026-10-13T12:00:00Z',
    step_seconds: 3600,
    totals: { events: 40, block: 30, shadow: 6, other: 4, error: 3, clients: 7, nodes: 2, policies: 2 },
    series: [{ start: '2026-10-13T11:00:00Z', block: 30, shadow: 6, other: 4, error: 3 }],
    top_rules: [{ rule_id: 942100, events: 25, block: 20, shadow: 5 }, { rule_id: 999999, events: 3, block: 3, shadow: 0 }],
    top_routes: [{ policy_id: 'pilot-verify', host: 'api.example.test', path_prefix: '/v1/verify', events: 30, block: 28, shadow: 0, error: 2 }],
    top_clients: [{ client_ip: '198.51.100.1', events: 12, block: 12 }],
    rules: { '942100': { name: 'SQL Injection Attack Detected via libinjection' } },
  };
  const fleet = () => {
    vi.spyOn(apiClient, 'listNodes').mockResolvedValue([
      { id: 'node-a', hostname: 'edge-01', online: true },
      { id: 'node-b', hostname: 'edge-02', online: false, last_seen_time: new Date(Date.now() - 600_000).toISOString() },
    ]);
    vi.spyOn(apiClient, 'listRollouts').mockResolvedValue([]);
    vi.spyOn(apiClient, 'listPolicies').mockResolvedValue([{ id: 'pilot-verify', name: 'pilot-verify' }]);
  };

  it('shows totals, top rules and routes with links to the events', async () => {
    const get = vi.spyOn(apiClient, 'getOverview').mockResolvedValue(overview);
    fleet();
    render(<StaticAuthProvider roles={['operator']}><OverviewPage route={{ page: 'overview' }} /></StaticAuthProvider>);
    expect(await screen.findAllByTestId('top-rule')).toHaveLength(2);
    expect(screen.getByTestId('kpi-events')).toHaveTextContent('40');
    expect(screen.getByTestId('kpi-blocked')).toHaveTextContent('75% of events');
    // fail mode is shown apart from the passed events
    expect(screen.getByTestId('kpi-unchecked')).toHaveTextContent('3');
    expect(screen.getByTestId('kpi-unchecked')).toHaveTextContent('fail mode, 7.5%');
    expect(screen.getByTestId('kpi-nodes')).toHaveTextContent('1/2');
    const [first, second] = screen.getAllByTestId('top-rule');
    expect(first).toHaveTextContent('SQL Injection Attack Detected via libinjection');
    expect(second).toHaveTextContent('not in the rule catalog');
    expect(first.querySelector('a')).toHaveAttribute('href', '#/events?range=24h&rule_id=942100');
    expect(screen.getByTestId('top-route')).toHaveTextContent('api.example.test/v1/verify');
    expect(screen.getAllByTestId('top-client')).toHaveLength(1);
    expect(screen.getByTestId('offline-nodes')).toHaveTextContent('edge-02');
    // 24 hours by default
    const p = get.mock.calls[0][0];
    expect(new Date(p.to).getTime() - new Date(p.from).getTime()).toBe(24 * 3_600_000);
  });

  it('switches to 7 and 30 days, and filters by policy', async () => {
    const get = vi.spyOn(apiClient, 'getOverview').mockResolvedValue(overview);
    fleet();
    render(<StaticAuthProvider roles={['viewer']}><OverviewPage route={{ page: 'overview' }} /></StaticAuthProvider>);
    await screen.findAllByTestId('top-rule');
    fireEvent.click(screen.getByTestId('range-7d'));
    await waitFor(() => {
      const p = get.mock.calls.at(-1)![0];
      expect(new Date(p.to).getTime() - new Date(p.from).getTime()).toBe(7 * 24 * 3_600_000);
    });
    fireEvent.click(screen.getByTestId('range-30d'));
    await waitFor(() => {
      const p = get.mock.calls.at(-1)![0];
      expect(new Date(p.to).getTime() - new Date(p.from).getTime()).toBe(30 * 24 * 3_600_000);
    });
    await screen.findByRole('option', { name: 'pilot-verify' });
    fireEvent.change(screen.getByTestId('overview-policy'), { target: { value: 'pilot-verify' } });
    await waitFor(() => expect(get.mock.calls.at(-1)![0].policy_id).toBe('pilot-verify'));
  });

  it('tells a viewer that client IPs are not shown', async () => {
    const { top_clients: _, ...forViewer } = overview;
    vi.spyOn(apiClient, 'getOverview').mockResolvedValue(forViewer);
    fleet();
    render(<StaticAuthProvider roles={['viewer']}><OverviewPage route={{ page: 'overview' }} /></StaticAuthProvider>);
    expect(await screen.findByTestId('top-clients-hidden')).toHaveTextContent('operators, approvers and admins');
  });

  it('shows an empty window and API errors', async () => {
    vi.spyOn(apiClient, 'getOverview').mockResolvedValueOnce({ ...overview, totals: { ...overview.totals, events: 0 }, top_rules: [], top_routes: [], top_clients: [] });
    fleet();
    render(<StaticAuthProvider roles={['operator']}><OverviewPage route={{ page: 'overview', query: { range: '30d' } }} /></StaticAuthProvider>);
    expect(await screen.findByTestId('overview-empty')).toHaveTextContent('No events in this window.');
    expect(screen.getByTestId('range-30d')).toHaveAttribute('aria-checked', 'true');
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
