import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor, act, within } from '@testing-library/react';
import { AuditPage } from '../pages/AuditPage';
import { StaticAuthProvider } from '../context/AuthContext';
import { apiClient, AuditEntry } from '../api/client';
import i18n from '../i18n';

const mockEntries: AuditEntry[] = [
  {
    at: '2026-10-16T12:00:00Z',
    actor: 'secops-alice',
    channel: 'ui',
    action: '/strata.admin.v1.FleetAdminService/RevokeNode',
    resource: 'nodes/node-edge-01',
    request_id: 'req-12345',
    before: { id: 'node-edge-01', revoked: false },
    after: { id: 'node-edge-01', revoked: true },
  },
  {
    at: '2026-10-16T11:30:00Z',
    actor: 'admin-bob',
    channel: 'api',
    action: '/strata.admin.v1.PolicyService/DeployPolicy',
    resource: 'policies/payment-api',
    request_id: 'req-67890',
    before: { version: 1, mode: 'shadow' },
    after: { version: 2, mode: 'enforce' },
  },
];

describe('AuditPage (Audit Trail & Non-repudiation)', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.spyOn(apiClient, 'getVersion').mockResolvedValue({ version: 'test', commit: '', api_version: 'v1' });
    void i18n.changeLanguage('en');
  });

  it('renders audit log entries and supports search filtering', async () => {
    vi.spyOn(apiClient, 'searchAuditLogs').mockResolvedValue({entries:mockEntries,has_more:false,limit:200});

    render(
      <StaticAuthProvider roles={['admin']}>
        <AuditPage />
      </StaticAuthProvider>
    );

    // Verify initial load
    await waitFor(() => {
      expect(screen.getByText('secops-alice')).toBeDefined();
      expect(screen.getByText('admin-bob')).toBeDefined();
    });

    const rows = screen.getAllByTestId('audit-row');
    expect(rows.length).toBe(2);

    // Search filter for "payment-api"
    const searchInput = screen.getByTestId('audit-search-input');
    fireEvent.change(searchInput, { target: { value: 'payment-api' } });

    expect(screen.queryByText('secops-alice')).toBeNull();
    expect(screen.getByText('admin-bob')).toBeDefined();

    // Reset filter
    const resetBtn = screen.getByTestId('audit-reset-filter-btn');
    fireEvent.click(resetBtn);

    expect(screen.getByText('secops-alice')).toBeDefined();
    expect(screen.getByText('admin-bob')).toBeDefined();
  });

  it('opens diff inspection modal with before/after state on click', async () => {
    vi.spyOn(apiClient, 'searchAuditLogs').mockResolvedValue({entries:mockEntries,has_more:false,limit:200});

    render(
      <StaticAuthProvider roles={['admin']}>
        <AuditPage />
      </StaticAuthProvider>
    );

    await waitFor(() => {
      expect(screen.getByText('secops-alice')).toBeDefined();
    });

    const inspectButtons = screen.getAllByTestId('audit-inspect-btn');
    expect(inspectButtons.length).toBeGreaterThan(0);

    // Click Diff button on first row (RevokeNode)
    fireEvent.click(inspectButtons[0]);

    // Inspect modal should open
    expect(screen.getByTestId('audit-inspect-dialog')).toBeDefined();
    expect(screen.getByText('Before State')).toBeDefined();
    expect(screen.getByText('After State')).toBeDefined();
    expect(screen.getByText(/"revoked": false/)).toBeDefined();
    expect(screen.getByText(/"revoked": true/)).toBeDefined();

    // Close modal
    const closeBtn = screen.getByTestId('audit-close-inspect-btn');
    fireEvent.click(closeBtn);
    expect(screen.queryByTestId('audit-inspect-dialog')).toBeNull();
  });

  it('sends actor, resource and time filters to the server before showing older matches', async () => {
    const read = vi.spyOn(apiClient, 'searchAuditLogs').mockResolvedValueOnce({entries: [], has_more: true, limit:200})
      .mockResolvedValue({entries: [mockEntries[1]], has_more:false, limit:200});
    render(<StaticAuthProvider roles={['admin']}><AuditPage /></StaticAuthProvider>);
    await screen.findByTestId('audit-result-scope');
    expect(screen.getByTestId('audit-result-scope').textContent).toContain('narrow the filters');
    fireEvent.change(screen.getByTestId('audit-filter-actor'), {target:{value:'admin-bob'}});
    fireEvent.change(screen.getByTestId('audit-filter-resource'), {target:{value:'payment-api'}});
    fireEvent.change(screen.getByTestId('audit-filter-from'), {target:{value:'2026-10-16T11:00'}});
    fireEvent.change(screen.getByTestId('audit-filter-to'), {target:{value:'2026-10-16T12:00'}});
    fireEvent.submit(screen.getByTestId('audit-server-filters'));
    await screen.findByText('admin-bob');
    expect(read.mock.calls.at(-1)?.[0]).toEqual({limit:200,actor:'admin-bob',resource:'payment-api',
      from:new Date('2026-10-16T11:00').toISOString(),to:new Date('2026-10-16T12:00').toISOString()});
    fireEvent.click(screen.getByTestId('audit-clear-server-filters'));
    await waitFor(() => expect(read.mock.calls.at(-1)?.[0]).toEqual({limit:200}));
  });

  it('ignores an older response even when the transport ignores abort', async () => {
    let finish!: (r:{entries:AuditEntry[];has_more:boolean;limit:number})=>void;
    const read=vi.spyOn(apiClient,'searchAuditLogs').mockImplementationOnce(()=>new Promise(resolve=>{finish=resolve;}))
      .mockResolvedValue({entries:[mockEntries[1]],has_more:false,limit:200});
    render(<StaticAuthProvider roles={['admin']}><AuditPage /></StaticAuthProvider>);
    fireEvent.change(screen.getByTestId('audit-filter-actor'),{target:{value:'admin-bob'}});
    fireEvent.submit(screen.getByTestId('audit-server-filters'));
    await screen.findByText('admin-bob');
    expect(read.mock.calls[0][1]?.aborted).toBe(true);
    await act(async()=>finish({entries:[mockEntries[0]],has_more:false,limit:200}));
    expect(screen.queryByText('secops-alice')).toBeNull();
    expect(screen.getByText('admin-bob')).toBeDefined();
  });

  it('does not display or export stale rows when refresh fails', async () => {
    vi.spyOn(apiClient,'searchAuditLogs').mockResolvedValueOnce({entries:mockEntries,has_more:false,limit:200}).mockRejectedValue(new Error('synthetic outage'));
    render(<StaticAuthProvider roles={['admin']}><AuditPage /></StaticAuthProvider>);
    await screen.findByText('admin-bob');
    fireEvent.click(screen.getByTestId('audit-refresh-btn'));
    await screen.findByTestId('audit-error');
    expect(screen.queryAllByTestId('audit-row')).toHaveLength(0);
    expect((screen.getByTestId('audit-export-btn') as HTMLButtonElement).disabled).toBe(true);
  });

  it('rejects an inverted time range without querying the API', async () => {
    const read=vi.spyOn(apiClient,'searchAuditLogs').mockResolvedValue({entries:[],has_more:false,limit:200});
    render(<StaticAuthProvider roles={['admin']}><AuditPage /></StaticAuthProvider>);
    await screen.findByTestId('audit-result-scope');
    fireEvent.change(screen.getByTestId('audit-filter-from'),{target:{value:'2026-10-18T12:00'}});
    fireEvent.change(screen.getByTestId('audit-filter-to'),{target:{value:'2026-10-17T12:00'}});
    fireEvent.submit(screen.getByTestId('audit-server-filters'));
    expect(screen.getByRole('alert').textContent).toContain('From earlier than To');
    expect(read).toHaveBeenCalledTimes(1);
  });

  it('preserves false/zero audit states and restores focus after Escape', async () => {
    vi.spyOn(apiClient,'searchAuditLogs').mockResolvedValue({entries:[{...mockEntries[0],before:false,after:0}],has_more:false,limit:200});
    render(<StaticAuthProvider roles={['admin']}><AuditPage /></StaticAuthProvider>);
    const trigger=await screen.findByTestId('audit-inspect-btn');
    trigger.focus();fireEvent.click(trigger);
    const dialog=screen.getByRole('dialog');
    expect(within(dialog).getByText('false')).toBeDefined();
    expect(within(dialog).getByText('0')).toBeDefined();
    expect(document.activeElement).toBe(screen.getByTestId('audit-close-inspect-btn'));
    fireEvent.keyDown(dialog,{key:'Escape'});
    expect(screen.queryByRole('dialog')).toBeNull();expect(document.activeElement).toBe(trigger);
  });
});
