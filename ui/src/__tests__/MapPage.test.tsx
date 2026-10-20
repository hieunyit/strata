import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor, within, act } from '@testing-library/react';
import { StaticAuthProvider } from '../context/AuthContext';
import { MapPage, applyDelta, logShade, eventsRequest } from '../pages/MapPage';
import { apiClient, Event, GeoCount, GeoFilters } from '../api/client';
import { SseParser, SseEvent } from '../lib/sse';
import { parseRoute } from '../router';
import i18n from '../i18n';

beforeEach(() => {
  vi.restoreAllMocks();
  vi.spyOn(apiClient, 'getVersion').mockResolvedValue({ version: 'test', commit: '', api_version: 'v1' });
  vi.spyOn(apiClient, 'listPolicies').mockResolvedValue([{ id: 'example-api', name: 'example-api' }]);
  vi.spyOn(apiClient, 'searchEvents').mockResolvedValue({ events: [], total_matched: 0 });
  void i18n.changeLanguage('en');
});

const row = (key: string, events: number, blocked = 0, extra: Partial<GeoCount> = {}): GeoCount => ({
  key,
  events,
  blocked,
  top_attack_type: 'sqli',
  ...extra,
});

describe('SSE parser', () => {
  it('splits events across chunks, skips comments, reads retry', () => {
    const p = new SseParser();
    expect(p.push('retry: 5000\n\nevent: snap')).toEqual([]);
    expect(p.retryMs).toBe(5000);
    expect(p.push('shot\ndata: {"a":1}\n')).toEqual([]);
    expect(p.push('\n: keepalive\n\nevent: delta\r\ndata: x\r\ndata: y\r\n\r\n')).toEqual([
      { event: 'snapshot', data: '{"a":1}' },
      { event: 'delta', data: 'x\ny' },
    ]);
    expect(p.push('data: plain\n\n')).toEqual([{ event: 'message', data: 'plain' }]);
  });
});

describe('map helpers', () => {
  it('applies deltas and shades on a log scale', () => {
    const rows = [row('VN', 3), row('US', 2), row('DE', 1)];
    const next = applyDelta(rows, { at: '', from: '', to: '', changed: [row('DE', 5), row('CN', 1)], removed: ['US'] });
    expect(next.map((r) => `${r.key}:${r.events}`)).toEqual(['DE:5', 'VN:3', 'CN:1']);
    expect(logShade(0, 10)).toBe(0);
    expect(logShade(10, 10)).toBe(1);
    expect(logShade(1, 1000)).toBeCloseTo(0.12, 2); // floor: a single event still shows
    expect(logShade(100, 1000)).toBeGreaterThan(0.6); // log scale, not 0.1
  });
  it('routes the map', () => {
    expect(parseRoute('#/map?range=7d&country=VN')).toEqual({ page: 'map', query: { range: '7d', country: 'VN' } });
  });
});

function mockStats() {
  const geo = vi.spyOn(apiClient, 'getGeo').mockImplementation(async (groupBy, from, to, f) => {
    const rows: Record<string, GeoCount[]> = {
      country: f.country ? [row(f.country, 4, 3)] : [row('VN', 4, 3), row('US', 2, 2, { top_attack_type: 'scanner' }), row('', 1)],
      city: [row('w7er', 4, 3, { label: 'Hanoi', lat: 21.0, lon: 105.8 })],
      asn: [row('7552', 3, 2, { label: 'Viettel' }), row('0', 1)],
      attack_type: [row('sqli', 3, 3), row('scanner', 2, 2)],
    };
    return { from, to, group_by: groupBy, rows: rows[groupBy], approximate: true };
  });
  const timeline = vi.spyOn(apiClient, 'getTimeline').mockImplementation(async (from, to) => ({
    from,
    to,
    step: '1h0m0s',
    approximate: true,
    buckets: [
      { start: '2026-10-19T10:00:00Z', block: 3, shadow: 1, error: 0, other: 1 },
      { start: '2026-10-19T11:00:00Z', block: 2, shadow: 0, error: 1, other: 1 },
    ],
  }));
  return { geo, timeline };
}

describe('map page (W18-F-01)', () => {
  it('shows every panel, and a click on a country filters them all at once', async () => {
    const { geo, timeline } = mockStats();
    vi.spyOn(apiClient, 'watchGeo').mockImplementation(async () => {});
    render(<StaticAuthProvider roles={['viewer']}><MapPage route={{ page: 'map' }} /></StaticAuthProvider>);

    const countries = await screen.findByTestId('map-countries');
    await waitFor(() => expect(within(countries).getAllByTestId('map-countries-row')).toHaveLength(3));
    expect(within(countries).getByText('Vietnam')).toBeInTheDocument();
    expect(within(countries).getByText('Unknown location')).toBeInTheDocument();
    expect(within(screen.getByTestId('map-cells')).getByText('Hanoi')).toBeInTheDocument();
    expect(within(screen.getByTestId('map-cells')).getByText('w7er · 21.00, 105.80')).toBeInTheDocument();
    expect(within(screen.getByTestId('map-asns')).getByText('AS7552')).toBeInTheDocument();
    expect(within(screen.getByTestId('map-attack-types')).getByText('Scanner')).toBeInTheDocument();
    expect(screen.getByTestId('map-basemap-pending')).toHaveTextContent('Hoàng Sa');
    expect(geo.mock.calls.map((c) => c[0]).sort()).toEqual(['asn', 'attack_type', 'city', 'country']);

    geo.mockClear();
    timeline.mockClear();
    fireEvent.click(within(countries).getByText('Vietnam'));
    await waitFor(() => expect(geo).toHaveBeenCalledTimes(4));
    for (const c of geo.mock.calls) expect((c[3] as GeoFilters).country).toBe('VN');
    expect((timeline.mock.calls[0][2] as GeoFilters).country).toBe('VN');
    expect(screen.getByTestId('map-chip')).toHaveTextContent('Country: Vietnam');
    expect(window.location.hash).toContain('country=VN');

    // removing the chip widens every panel again
    geo.mockClear();
    fireEvent.click(screen.getByRole('button', { name: 'Remove the Country filter' }));
    await waitFor(() => expect(geo).toHaveBeenCalledTimes(4));
    for (const c of geo.mock.calls) expect((c[3] as GeoFilters).country).toBeUndefined();
    expect(screen.queryByTestId('map-chip')).not.toBeInTheDocument();
  });

  it('combines filters from the route, the verdict switch and the ASN panel', async () => {
    const { geo } = mockStats();
    vi.spyOn(apiClient, 'watchGeo').mockImplementation(async () => {});
    render(
      <StaticAuthProvider roles={['viewer']}>
        <MapPage route={{ page: 'map', query: { range: '7d', attack_type: 'sqli', ignored: 'x' } }} />
      </StaticAuthProvider>,
    );
    await waitFor(() => expect(geo).toHaveBeenCalled());
    expect((geo.mock.calls[0][3] as GeoFilters)).toEqual({ attack_type: 'sqli' });
    geo.mockClear();
    fireEvent.click(screen.getByTestId('map-action-block'));
    await waitFor(() => expect(geo).toHaveBeenCalledTimes(4));
    expect(geo.mock.calls[0][3]).toEqual({ attack_type: 'sqli', action: 'block' });
    geo.mockClear();
    fireEvent.click(await within(screen.getByTestId('map-asns')).findByText('AS7552'));
    await waitFor(() => expect(geo).toHaveBeenCalledTimes(4));
    expect(geo.mock.calls[0][3]).toEqual({ attack_type: 'sqli', action: 'block', asn: '7552' });
    // the unknown ASN is not a filter
    geo.mockClear();
    fireEvent.click(within(screen.getByTestId('map-asns')).getByText('Unknown ASN'));
    await new Promise((r) => setTimeout(r, 50));
    expect(geo).not.toHaveBeenCalled();
    expect(screen.getAllByTestId('map-chip')).toHaveLength(3);
    fireEvent.click(screen.getByTestId('map-clear'));
    await waitFor(() => expect(screen.queryByTestId('map-chip')).not.toBeInTheDocument());
  });

  it('follows the live stream: snapshot and deltas on the country layer', async () => {
    mockStats();
    let emit: ((e: SseEvent) => void) | undefined;
    let state: ((c: boolean, e?: string) => void) | undefined;
    const watch = vi.spyOn(apiClient, 'watchGeo').mockImplementation(async (_groupBy, _span, _f, onEvent, onState, signal) => {
      emit = onEvent;
      state = onState;
      await new Promise<void>((done) => signal.addEventListener('abort', () => done()));
    });
    const { unmount } = render(<StaticAuthProvider roles={['viewer']}><MapPage route={{ page: 'map', query: { range: '1h' } }} /></StaticAuthProvider>);
    const countries = await screen.findByTestId('map-countries');
    await waitFor(() => expect(within(countries).getAllByTestId('map-countries-row')).toHaveLength(3));
    expect(watch).toHaveBeenCalledTimes(1);
    expect(watch.mock.calls[0][0]).toBe('country');
    expect(watch.mock.calls[0][1]).toBe('1h');

    act(() => {
      state!(true);
      emit!({ event: 'delta', data: JSON.stringify({ at: '', from: '', to: '', changed: [row('DE', 9, 9)], removed: ['US'] }) });
    });
    await waitFor(() => expect(within(countries).getAllByTestId('map-countries-row')[0]).toHaveAttribute('data-key', 'DE'));
    expect(within(countries).queryByText('United States')).not.toBeInTheDocument();
    expect(screen.getByTestId('map-status')).toHaveTextContent('Live');
    act(() => emit!({ event: 'delta', data: 'not json' })); // skipped
    expect(within(countries).getAllByTestId('map-countries-row')).toHaveLength(3);

    // pause stops the stream
    const signal = watch.mock.calls[0][5] as AbortSignal;
    fireEvent.click(screen.getByTestId('map-live'));
    await waitFor(() => expect(signal.aborted).toBe(true));
    unmount();
  });

  it('has no live mode for 30 days', async () => {
    mockStats();
    const watch = vi.spyOn(apiClient, 'watchGeo').mockImplementation(async () => {});
    render(<StaticAuthProvider roles={['viewer']}><MapPage route={{ page: 'map', query: { range: '30d' } }} /></StaticAuthProvider>);
    await screen.findByTestId('map-countries');
    expect(screen.getByTestId('map-live')).toBeDisabled();
    expect(screen.getByTestId('map-status')).toHaveTextContent('No live mode for 30 days');
    expect(watch).not.toHaveBeenCalled();
  });
});

describe('map events (W19-F-01)', () => {
  it('lists the events behind the panels with the same filters, a row opens the decision trace', async () => {
    mockStats();
    vi.spyOn(apiClient, 'watchGeo').mockImplementation(async () => {});
    const search = vi.spyOn(apiClient, 'searchEvents').mockResolvedValue({
      events: [{ block_id: 'STR-AAAA-BBBB-CCCC-DDDD', timestamp: '2026-10-19T10:00:00Z', action: 'block', matched_rules: [942100], client_ip: '198.51.100.7', policy_id: 'example-api' } as Event],
      total_matched: 41,
      next_page_token: 'p2',
    });
    render(<StaticAuthProvider roles={['viewer']}><MapPage route={{ page: 'map', query: { range: '7d' } }} /></StaticAuthProvider>);
    const panel = await screen.findByTestId('map-events');
    await within(panel).findByText('STR-AAAA-BBBB-CCCC-DDDD');
    expect(search.mock.calls[0][0]).toMatchObject({ page_size: 20 });
    expect(search.mock.calls[0][0].country).toBeUndefined();

    // a country picked on the page narrows the table too
    search.mockClear();
    fireEvent.click(within(await screen.findByTestId('map-countries')).getByText('Vietnam'));
    await waitFor(() => expect(search).toHaveBeenCalled());
    expect(search.mock.calls[0][0]).toMatchObject({ country: 'VN', page_size: 20 });
    expect(search.mock.calls[0][0].page_token).toBeUndefined();

    // the next page, then a row opens the event
    search.mockClear();
    fireEvent.click(within(panel).getByRole('button', { name: /next/i }));
    await waitFor(() => expect(search).toHaveBeenCalled());
    expect(search.mock.calls[0][0]).toMatchObject({ country: 'VN', page_token: 'p2' });
    fireEvent.click(within(panel).getByTestId('event-row'));
    expect(window.location.hash).toBe('#/events/STR-AAAA-BBBB-CCCC-DDDD');
  });

  it('builds the search from the map filters', () => {
    const r = eventsRequest('24h', { policy_id: 'example-api', action: 'block', country: 'VN', asn: '7552', attack_type: 'sqli' }, 'tok');
    expect(r).toMatchObject({ policy_id: 'example-api', action: 'block', country: 'VN', asn: 7552, attack_type: 'sqli', page_size: 20, page_token: 'tok' });
    expect(new Date(r.to!).getTime() - new Date(r.from!).getTime()).toBe(24 * 3600 * 1000);
  });
});
