import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { StaticAuthProvider } from '../context/AuthContext';
import { EventsTable } from '../components/events/EventsTable';
import { EventTrace } from '../components/events/EventTrace';
import { EventFilterBar, emptyFilters } from '../components/events/EventFilterBar';
import { EventsPage, filtersFromQuery, searchRequest } from '../pages/EventsPage';
import { EventDetailPage } from '../pages/EventDetailPage';
import { Header } from '../components/layout/Header';
import { Event, apiClient, ApiError } from '../api/client';
import i18n from '../i18n';

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
  violations: [{ rule_id: 942100, layer: 'sqli', field: 'body.query', snippet: "' OR 1=1 --" }],
  received_at: new Date().toISOString(),
};

beforeEach(() => {
  vi.restoreAllMocks();
  vi.spyOn(apiClient, 'getVersion').mockResolvedValue({ version: 'test', commit: '', api_version: 'v1' });
  void i18n.changeLanguage('en');
  window.location.hash = '';
});

describe('events table', () => {
  it('shows the Block ID, verdict, request and score', () => {
    render(
      <StaticAuthProvider roles={['operator']}>
        <EventsTable events={[mockEvent]} isLoading={false} totalMatched={1} />
      </StaticAuthProvider>,
    );
    expect(screen.getByText('STR-8F3K-Q2VD-7XNM-A1PC')).toBeInTheDocument();
    expect(screen.getByText('POST')).toBeInTheDocument();
    expect(screen.getByText('/v1/users/search')).toBeInTheDocument();
    expect(screen.getByTestId('verdict')).toHaveAttribute('data-verdict', 'block');
    expect(screen.getByText('45')).toBeInTheDocument();
    expect(screen.getByTestId('events-total')).toHaveTextContent('1–1 of 1');
  });

  it('opens the event page when a row is selected', () => {
    render(
      <StaticAuthProvider roles={['operator']}>
        <EventsTable events={[mockEvent]} isLoading={false} totalMatched={1} />
      </StaticAuthProvider>,
    );
    fireEvent.click(screen.getByTestId('event-row'));
    expect(window.location.hash).toBe('#/events/STR-8F3K-Q2VD-7XNM-A1PC');
  });

  it('masks the client IP for a viewer', () => {
    render(
      <StaticAuthProvider roles={['viewer']}>
        <EventsTable events={[mockEvent]} isLoading={false} totalMatched={1} />
      </StaticAuthProvider>,
    );
    expect(screen.getByTestId('table-client-ip')).toHaveTextContent('198.51.***.***');
  });
});

describe('event filters', () => {
  it('reads filters from the URL and builds the search request', () => {
    const f = filtersFromQuery({ range: '7d', action: 'shadow', rule_id: '942100', client_ip: '198.51.100.1', bogus: 'x' });
    expect(f).toMatchObject({ range: '7d', action: 'shadow', rule_id: '942100', client_ip: '198.51.100.1' });
    expect(filtersFromQuery({ range: '90d' }).range).toBe('24h');
    const req = searchRequest(f);
    expect(req.rule_id).toBe(942100);
    expect(req.action).toBe('shadow');
    expect(new Date(req.to!).getTime() - new Date(req.from!).getTime()).toBe(7 * 24 * 3_600_000);
  });

  it('applies a new time range at once and the other filters on submit', () => {
    const apply = vi.fn();
    render(
      <StaticAuthProvider roles={['operator']}>
        <EventFilterBar initial={emptyFilters} onApply={apply} />
      </StaticAuthProvider>,
    );
    fireEvent.click(screen.getByTestId('range-30d'));
    expect(apply).toHaveBeenLastCalledWith(expect.objectContaining({ range: '30d' }));
    fireEvent.change(screen.getByTestId('rule-id-filter-input'), { target: { value: '94a2100' } });
    fireEvent.change(screen.getByTestId('action-filter-select'), { target: { value: 'pass' } });
    fireEvent.click(screen.getByTestId('apply-filters-btn'));
    expect(apply).toHaveBeenLastCalledWith(expect.objectContaining({ range: '30d', rule_id: '942100', action: 'pass' }));
  });

  it('the Events page searches with the filters of its route', async () => {
    const search = vi.spyOn(apiClient, 'searchEvents').mockResolvedValue({ events: [mockEvent], total_matched: 1 });
    render(
      <StaticAuthProvider roles={['operator']}>
        <EventsPage route={{ page: 'events', query: { range: '30d', rule_id: '942100' } }} />
      </StaticAuthProvider>,
    );
    await screen.findByTestId('event-row');
    const req = search.mock.calls[0][0];
    expect(req.rule_id).toBe(942100);
    expect(new Date(req.to!).getTime() - new Date(req.from!).getTime()).toBe(30 * 24 * 3_600_000);
  });
});

describe('decision trace', () => {
  it('masks client IP and payload snippet for a viewer', () => {
    render(
      <StaticAuthProvider roles={['viewer']}>
        <EventTrace event={mockEvent} />
      </StaticAuthProvider>,
    );
    expect(screen.getByTestId('detail-client-ip').textContent).toBe('198.51.***.***');
    const snippet = screen.getByTestId('violation-snippet');
    expect(snippet.textContent).toContain('[REDACTED FOR VIEWER ROLE]');
    expect(snippet.textContent).not.toContain("' OR 1=1 --");
    expect(screen.getByTestId('viewer-notice')).toBeInTheDocument();
    // no pivot on a client IP the viewer cannot see
    expect(screen.queryByTestId('link-same-ip')).not.toBeInTheDocument();
  });

  it('shows the full IP, the snippet and the reason to an operator', () => {
    render(
      <StaticAuthProvider roles={['operator']}>
        <EventTrace event={mockEvent} />
      </StaticAuthProvider>,
    );
    expect(screen.getByTestId('detail-client-ip').textContent).toBe('198.51.100.42');
    expect(screen.getByTestId('violation-snippet').textContent).toBe("' OR 1=1 --");
    expect(screen.queryByTestId('viewer-notice')).not.toBeInTheDocument();
    expect(screen.getByTestId('verdict-summary')).toHaveTextContent('Blocked by policy example-api (version 1) with an anomaly score of 45 from 2 matching rules.');
    // 942150 matched without a recorded violation
    expect(screen.getByTestId('extra-rules')).toHaveTextContent('942150');
    expect(screen.getByTestId('link-same-ip')).toHaveAttribute('href', '#/events?client_ip=198.51.100.42&range=7d');
    // the raw event, masked the same way
    fireEvent.click(screen.getByTestId('raw-toggle'));
    expect(screen.getByTestId('raw-json').textContent).toContain('"block_id": "STR-8F3K-Q2VD-7XNM-A1PC"');
  });
});

describe('event page', () => {
  it('loads the event of its Block ID', async () => {
    const get = vi.spyOn(apiClient, 'getEvent').mockResolvedValue({ event: mockEvent });
    render(
      <StaticAuthProvider roles={['operator']}>
        <EventDetailPage blockId="str-8f3k-q2vd-7xnm-a1pc" />
      </StaticAuthProvider>,
    );
    expect(await screen.findByTestId('event-detail')).toBeInTheDocument();
    expect(get).toHaveBeenCalledWith('STR-8F3K-Q2VD-7XNM-A1PC');
    expect(screen.getByTestId('detail-block-id')).toHaveTextContent('STR-8F3K-Q2VD-7XNM-A1PC');
  });

  it('says so when the Block ID is unknown', async () => {
    vi.spyOn(apiClient, 'getEvent').mockRejectedValue(new ApiError('event not found', 404));
    render(
      <StaticAuthProvider roles={['operator']}>
        <EventDetailPage blockId="STR-AAAA-BBBB-CCCC-DDDD" />
      </StaticAuthProvider>,
    );
    expect(await screen.findByTestId('event-missing')).toHaveTextContent('No event with Block ID STR-AAAA-BBBB-CCCC-DDDD');
  });
});

describe('header', () => {
  it('opens the page of a searched Block ID', async () => {
    render(
      <StaticAuthProvider roles={['operator']}>
        <Header />
      </StaticAuthProvider>,
    );
    fireEvent.change(screen.getByTestId('block-id-search-input'), { target: { value: ' str-8f3k-q2vd-7xnm-a1pc ' } });
    fireEvent.click(screen.getByTestId('block-id-search-btn'));
    await waitFor(() => expect(window.location.hash).toBe('#/events/STR-8F3K-Q2VD-7XNM-A1PC'));
  });

  it('refuses what is not a Block ID', () => {
    const search = vi.fn();
    render(
      <StaticAuthProvider roles={['operator']}>
        <Header onSearchBlockId={search} />
      </StaticAuthProvider>,
    );
    fireEvent.change(screen.getByTestId('block-id-search-input'), { target: { value: 'ABC-123' } });
    fireEvent.click(screen.getByTestId('block-id-search-btn'));
    expect(screen.getByRole('alert')).toHaveTextContent('starts with STR- or EVT-');
    fireEvent.change(screen.getByTestId('block-id-search-input'), { target: { value: 'STR-123' } });
    fireEvent.click(screen.getByTestId('block-id-search-btn'));
    expect(screen.getByRole('alert')).toHaveTextContent('four groups');
    expect(search).not.toHaveBeenCalled();
  });
});
