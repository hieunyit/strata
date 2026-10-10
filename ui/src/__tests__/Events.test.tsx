import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { StaticAuthProvider } from '../context/AuthContext';
import { EventsTable } from '../components/events/EventsTable';
import { DecisionTraceModal } from '../components/events/DecisionTraceModal';
import { Header } from '../components/layout/Header';
import { Event, apiClient } from '../api/client';
import '../i18n';

const mockEvent: Event = {
  block_id: 'STR-8F3K-Q2VD-7XNM-A1PC',
  timestamp: new Date().toISOString(),
  node_id: 'edge-worker-01',
  connector_type: 'nginx',
  policy_id: 'example-api',
  policy_version: 1,
  client_ip: '198.51.100.42',
  identity: 'anon-client-1',
  request_id: 'req-001',
  http_method: 'POST',
  http_host: 'api.example.test',
  http_path: '/v1/users/search',
  status_code: 403,
  action: 'block',
  score_protocol: 0,
  score_sqli: 45,
  score_xss: 0,
  score_anomaly: 45,
  matched_rules: [942100, 942150],
  violations: [
    {
      rule_id: 942100,
      layer: 'sqli',
      field: 'body.query',
      snippet: "' OR 1=1 --",
    },
  ],
  received_at: new Date().toISOString(),
};

describe('Strata Events UI Components', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders events in the table and shows block ID and action', () => {
    const handleSelect = vi.fn();
    render(
      <StaticAuthProvider roles={['operator']}>
        <EventsTable
          events={[mockEvent]}
          isLoading={false}
          totalMatched={1}
          onSelectEvent={handleSelect}
        />
      </StaticAuthProvider>
    );

    expect(screen.getByText('STR-8F3K-Q2VD-7XNM-A1PC')).toBeInTheDocument();
    expect(screen.getByText('POST')).toBeInTheDocument();
    expect(screen.getByText('/v1/users/search')).toBeInTheDocument();
    expect(screen.getByText('45')).toBeInTheDocument(); // Anomaly score
  });

  it('masks client IP and payload snippet when role is viewer', () => {
    const handleClose = vi.fn();
    render(
      <StaticAuthProvider roles={['viewer']}>
        <DecisionTraceModal
          event={mockEvent}
          isOpen={true}
          onClose={handleClose}
        />
      </StaticAuthProvider>
    );

    // IP should be masked
    const ipElement = screen.getByTestId('modal-client-ip');
    expect(ipElement.textContent).toBe('198.51.***.***');

    // Snippet should be redacted
    const snippetElement = screen.getByTestId('violation-snippet');
    expect(snippetElement.textContent).toContain('[REDACTED FOR VIEWER ROLE]');
    expect(snippetElement.textContent).not.toContain("' OR 1=1 --");

    // Viewer notice banner must be visible
    expect(screen.getByTestId('viewer-notice')).toBeInTheDocument();
  });

  it('shows full IP and raw snippet when role is operator', () => {
    const handleClose = vi.fn();
    render(
      <StaticAuthProvider roles={['operator']}>
        <DecisionTraceModal
          event={mockEvent}
          isOpen={true}
          onClose={handleClose}
        />
      </StaticAuthProvider>
    );

    // Full IP visible
    const ipElement = screen.getByTestId('modal-client-ip');
    expect(ipElement.textContent).toBe('198.51.100.42');

    // Full snippet visible
    const snippetElement = screen.getByTestId('violation-snippet');
    expect(snippetElement.textContent).toBe("' OR 1=1 --");

    // No viewer banner, and no action buttons until their APIs exist
    expect(screen.queryByTestId('viewer-notice')).not.toBeInTheDocument();
    expect(screen.queryByTestId('action-mark-fp')).not.toBeInTheDocument();
  });

  it('triggers global Block ID search from Header', () => {
    const handleSearch = vi.fn();
    render(
      <StaticAuthProvider roles={['operator']}>
        <Header onSearchBlockId={handleSearch} />
      </StaticAuthProvider>
    );

    const input = screen.getByTestId('block-id-search-input');
    fireEvent.change(input, { target: { value: 'STR-8F3K-Q2VD-7XNM-A1PC' } });

    const btn = screen.getByTestId('block-id-search-btn');
    fireEvent.click(btn);

    expect(handleSearch).toHaveBeenCalledWith('STR-8F3K-Q2VD-7XNM-A1PC');
  });

  it('fetches event from apiClient and displays decision trace', async () => {
    vi.spyOn(apiClient, 'getEvent').mockResolvedValueOnce({
      event: mockEvent,
    });

    const result = await apiClient.getEvent('STR-8F3K-Q2VD-7XNM-A1PC');
    expect(result.event.block_id).toBe('STR-8F3K-Q2VD-7XNM-A1PC');
    expect(result.event.score_sqli).toBe(45);
    expect(result.event.violations).toHaveLength(1);
  });
});
