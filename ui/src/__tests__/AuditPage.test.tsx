import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
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
    vi.spyOn(apiClient, 'listAuditLogs').mockResolvedValue(mockEntries);

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
    vi.spyOn(apiClient, 'listAuditLogs').mockResolvedValue(mockEntries);

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
});
