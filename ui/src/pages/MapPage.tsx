import React, { useCallback, useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Pause, Play, RefreshCw, X, MapPinOff } from 'lucide-react';
import { AppShell } from '../components/layout/AppShell';
import { PageHeader, RangeSwitch, ErrorBanner, SectionTitle, Empty, formatCount } from '../components/ui';
import { StrataChart } from '../components/overview/StrataChart';
import { apiClient, Event, GeoCount, GeoBucket, GeoDelta, GeoFilters, GeoSnapshot, Policy, SearchEventsRequest, isEventsUnavailable } from '../api/client';
import { EventsTable } from '../components/events/EventsTable';
import { RangeKey, isRange, windowOf } from '../lib/timeRange';
import { Route, replaceQuery } from '../router';
import { GeoBlockAction } from '../components/map/GeoBlockAction';
import { useAuth } from '../context/AuthContext';
import { canWritePolicies } from '../auth/roles';

// Attack map (W18-F-01, nginx-module.md › Bản đồ GeoIP › Hiển thị): one
// filter set for every panel; a click on a country, ASN or attack type
// narrows the whole page. The base map (W17-F-01) waits for the PO's check
// of the tiles' borders (Hoàng Sa, Trường Sa): the layers are shown as
// ranked panels until then, never on an unchecked base map.

const ranges: RangeKey[] = ['1h', '24h', '7d', '30d'];
// sliding window of the live stream (at most 168h): none for 30 days
const liveWindow: Partial<Record<RangeKey, string>> = { '1h': '1h', '24h': '24h', '7d': '168h' };
const actions = ['block', 'shadow', 'pass', 'error'] as const;
const filterKeys = ['policy_id', 'action', 'attack_type', 'country', 'asn'] as const;
// other panels follow the live country stream at most this often
const REST_THROTTLE_MS = 10_000;

const EVENTS_PAGE = 20;

// W19-F-01: the events behind the page's numbers, with the same window and
// filters (the search counts countries, ASNs and attack types as the
// aggregates do)
export function eventsRequest(range: RangeKey, f: GeoFilters, pageToken?: string): SearchEventsRequest {
  return {
    ...windowOf(range),
    policy_id: f.policy_id || undefined,
    action: (f.action || undefined) as SearchEventsRequest['action'],
    country: f.country || undefined,
    asn: f.asn ? Number(f.asn) : undefined,
    attack_type: f.attack_type || undefined,
    page_size: EVENTS_PAGE,
    page_token: pageToken,
  };
}

interface Data {
  countries: GeoCount[];
  cells: GeoCount[];
  asns: GeoCount[];
  types: GeoCount[];
  timeline: GeoBucket[];
}

function filtersOf(query: Record<string, string> | undefined): GeoFilters {
  const f: GeoFilters = {};
  for (const k of filterKeys) if (query?.[k]) f[k] = query[k];
  return f;
}

function sortRows(rows: GeoCount[]): GeoCount[] {
  return [...rows].sort((a, b) => b.events - a.events || a.key.localeCompare(b.key));
}

export function applyDelta(rows: GeoCount[], d: GeoDelta): GeoCount[] {
  const m = new Map(rows.map((r) => [r.key, r]));
  for (const k of d.removed ?? []) m.delete(k);
  for (const r of d.changed ?? []) m.set(r.key, r);
  return sortRows([...m.values()]);
}

/** opacity of a count on a log scale, as the country layer will shade it */
export function logShade(n: number, max: number): number {
  if (max <= 0 || n <= 0) return 0;
  return Math.max(0.12, Math.log1p(n) / Math.log1p(max));
}

function stepSeconds(b: GeoBucket[]): number {
  return b.length > 1 ? (Date.parse(b[1].start) - Date.parse(b[0].start)) / 1000 : 3600;
}

const RankPanel: React.FC<{
  title: string;
  aside?: string;
  rows: GeoCount[];
  label: (r: GeoCount) => string;
  sub?: (r: GeoCount) => string | undefined;
  active?: string;
  onPick?: (r: GeoCount) => void;
  testId: string;
  empty: string;
  locale: string;
}> = ({ title, aside, rows, label, sub, active, onPick, testId, empty, locale }) => {
  const max = rows.reduce((m, r) => Math.max(m, r.events), 0);
  return (
    <section className="panel" data-testid={testId}>
      <SectionTitle aside={aside}>{title}</SectionTitle>
      {rows.length === 0 ? (
        <Empty>{empty}</Empty>
      ) : (
        <ul className="divide-y divide-line text-[13px]">
          {rows.map((r) => (
            <li key={r.key}>
              <button
                type="button"
                data-testid={`${testId}-row`}
                data-key={r.key}
                aria-pressed={active === r.key}
                disabled={!onPick}
                onClick={() => onPick?.(r)}
                className={`flex w-full items-center gap-3 px-4 py-2 text-left hover:bg-sunken/60 disabled:cursor-default ${active === r.key ? 'bg-sunken' : ''}`}
              >
                <span className="h-3 w-3 shrink-0 rounded-sm bg-block" style={{ opacity: logShade(r.events, max) }} aria-hidden />
                <span className="min-w-0 flex-1">
                  <span className="block truncate">{label(r)}</span>
                  {sub?.(r) && <span className="block truncate text-xs text-muted">{sub(r)}</span>}
                </span>
                <span className="w-16 text-right tabular-nums text-block">{formatCount(r.blocked, locale)}</span>
                <span className="w-16 text-right tabular-nums">{formatCount(r.events, locale)}</span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
};

export const MapPage: React.FC<{ route: Route }> = ({ route }) => {
  const { t, i18n } = useTranslation();
  const locale = i18n.language;
  const [range, setRange] = useState<RangeKey>(isRange(route.query?.range, ranges) ? (route.query!.range as RangeKey) : '24h');
  const [filters, setFilters] = useState<GeoFilters>(() => filtersOf(route.query));
  const [policies, setPolicies] = useState<Policy[]>([]);
  const { roles } = useAuth();
  const [data, setData] = useState<Data | undefined>();
  const [error, setError] = useState<string | undefined>();
  const [loading, setLoading] = useState(true);
  const [live, setLive] = useState(true);
  const [stream, setStream] = useState<{ connected: boolean; error?: string }>({ connected: false });
  const [updated, setUpdated] = useState<Date | undefined>();
  const generation = useRef(0);
  const lastRest = useRef(0);
  const [events, setEvents] = useState<{ list: Event[]; total: number; next?: string; error?: string }>({ list: [], total: 0 });
  const [eventPages, setEventPages] = useState<string[]>(['']); // page tokens, the first is ''
  const [eventPage, setEventPage] = useState(0);
  const [eventsLoading, setEventsLoading] = useState(true);

  const regionName = useCallback(
    (code: string) => {
      if (code === '') return t('map.unknownCountry');
      if (code === 'INTERNAL') return t('map.internal');
      try {
        return new Intl.DisplayNames([locale], { type: 'region' }).of(code) ?? code;
      } catch {
        return code;
      }
    },
    [locale, t],
  );
  const attackName = (k: string) => t(`map.attack.${k}`, { defaultValue: k });

  // every panel from one read: a filter change updates them together
  const refresh = useCallback(
    async (onlyRest = false) => {
      const gen = ++generation.current;
      const { from, to } = windowOf(range);
      try {
        const [countries, cells, asns, types, timeline] = await Promise.all([
          onlyRest ? undefined : apiClient.getGeo('country', from, to, filters, 20),
          apiClient.getGeo('city', from, to, filters, 20),
          apiClient.getGeo('asn', from, to, filters, 10),
          apiClient.getGeo('attack_type', from, to, filters, 14),
          apiClient.getTimeline(from, to, filters),
        ]);
        if (gen !== generation.current) return; // a newer read is under way
        setData((d) => ({
          countries: countries ? countries.rows : (d?.countries ?? []),
          cells: cells.rows,
          asns: asns.rows,
          types: types.rows,
          timeline: timeline.buckets,
        }));
        setError(undefined);
        setUpdated(new Date());
        lastRest.current = Date.now();
      } catch (e) {
        if (gen !== generation.current) return;
        if (isEventsUnavailable(e)) {
          setData(undefined); // no map rather than an empty one (CP-A08)
          setError(t('errors.eventsUnavailable'));
          return;
        }
        setError(e instanceof Error ? e.message : String(e));
      } finally {
        if (gen === generation.current) setLoading(false);
      }
    },
    [range, filters],
  );

  // the events table: first page on every filter or window change, the
  // chosen page otherwise
  const loadEvents = useCallback(
    async (page: number, tokens: string[]) => {
      setEventsLoading(true);
      try {
        const res = await apiClient.searchEvents(eventsRequest(range, filters, tokens[page] || undefined));
        setEvents({ list: res.events ?? [], total: res.total_matched ?? 0, next: res.next_page_token || undefined });
      } catch (e) {
        setEvents({ list: [], total: 0, error: isEventsUnavailable(e) ? t('errors.eventsUnavailable') : e instanceof Error ? e.message : String(e) });
      } finally {
        setEventsLoading(false);
      }
    },
    [range, filters, t],
  );
  useEffect(() => {
    setEventPage(0);
    setEventPages(['']);
    void loadEvents(0, ['']);
  }, [loadEvents]);

  useEffect(() => {
    setLoading(true);
    void refresh();
    replaceQuery({ page: 'map', query: { range, ...(filters as Record<string, string>) } });
  }, [refresh, range, filters]);

  useEffect(() => {
    apiClient.listPolicies().then(setPolicies).catch(() => {});
  }, []);

  // live: the country layer from the stream, the other panels re-read
  // when it changes (throttled)
  const span = liveWindow[range];
  useEffect(() => {
    if (!live || !span) {
      setStream({ connected: false });
      return;
    }
    const ctl = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const followRest = () => {
      if (timer) return;
      const wait = Math.max(0, lastRest.current + REST_THROTTLE_MS - Date.now());
      timer = setTimeout(() => {
        timer = undefined;
        void refresh(true);
      }, wait);
    };
    void apiClient.watchGeo(
      'country',
      span,
      filters,
      (e) => {
        try {
          if (e.event === 'snapshot') {
            const s = JSON.parse(e.data) as GeoSnapshot;
            setData((d) => (d ? { ...d, countries: sortRows(s.rows) } : d));
          } else if (e.event === 'delta') {
            const d = JSON.parse(e.data) as GeoDelta;
            setData((cur) => (cur ? { ...cur, countries: applyDelta(cur.countries, d) } : cur));
            setUpdated(new Date());
            followRest();
          }
        } catch {
          // a malformed event is skipped; the next snapshot repairs the view
        }
      },
      (connected, err) => setStream({ connected, error: err }),
      ctl.signal,
    );
    return () => {
      ctl.abort();
      if (timer) clearTimeout(timer);
    };
  }, [live, span, filters, refresh]);

  const setFilter = (k: keyof GeoFilters, v: string | undefined) =>
    setFilters((f) => {
      const n = { ...f };
      if (v && f[k] !== v) n[k] = v;
      else delete n[k];
      return n;
    });

  const chips = filterKeys.filter((k) => filters[k]);
  const chipText = (k: keyof GeoFilters, v: string) =>
    k === 'country' ? regionName(v) : k === 'attack_type' ? attackName(v) : k === 'action' ? t(`verdict.${v === 'error' ? 'unchecked' : v}`) : k === 'asn' ? `AS${v}` : v;
  const d = data;
  const total = d?.timeline.reduce((n, b) => n + b.block + b.shadow + b.other, 0) ?? 0;
  const empty = loading ? t('common.loading') : t('map.noEvents');

  return (
    <AppShell active="map" wide>
      <PageHeader
        title={t('map.title')}
        description={t('map.subtitle')}
        actions={
          <>
            <label className="sr-only" htmlFor="map-policy">
              {t('overview.policy')}
            </label>
            <select
              id="map-policy"
              data-testid="map-policy"
              value={filters.policy_id ?? ''}
              onChange={(e) => setFilter('policy_id', e.target.value || undefined)}
              className="field w-auto min-w-[11rem]"
            >
              <option value="">{t('overview.allPolicies')}</option>
              {policies.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name || p.id}
                </option>
              ))}
            </select>
            <RangeSwitch value={range} options={ranges} onChange={setRange} />
            <button type="button" className="btn" data-testid="map-live" onClick={() => setLive(!live)} aria-pressed={!live} disabled={!span}>
              {live && span ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
              {live && span ? t('common.pause') : t('common.resume')}
            </button>
            <button type="button" className="btn" onClick={() => void refresh()} aria-label={t('common.refresh')} title={t('common.refresh')}>
              <RefreshCw className="w-3.5 h-3.5" />
            </button>
          </>
        }
      />
      <ErrorBanner message={error && t('common.refreshError', { error })} />

      <div className="mb-4 flex flex-wrap items-center gap-2" data-testid="map-filters">
        <div role="radiogroup" aria-label={t('map.action')} className="inline-flex rounded border border-line bg-surface p-0.5">
          {actions.map((a) => (
            <button
              key={a}
              type="button"
              role="radio"
              aria-checked={filters.action === a}
              data-testid={`map-action-${a}`}
              onClick={() => setFilter('action', a)}
              className={`h-7 px-3 rounded-sm text-[13px] ${filters.action === a ? 'bg-ink text-paper font-medium' : 'text-muted hover:text-ink'}`}
            >
              {t(`verdict.${a === 'error' ? 'unchecked' : a}`)}
            </button>
          ))}
        </div>
        {chips.map((k) => (
          <span key={k} data-testid="map-chip" data-filter={k} className="inline-flex items-center gap-1 rounded-full border border-line bg-surface pl-3 pr-1 h-7 text-[13px]">
            <span className="text-muted">{t(`map.filter.${k}`)}:</span> {chipText(k, filters[k]!)}
            <button type="button" aria-label={t('map.removeFilter', { name: t(`map.filter.${k}`) })} onClick={() => setFilter(k, undefined)} className="rounded-full p-1 hover:bg-sunken">
              <X className="w-3 h-3" />
            </button>
          </span>
        ))}
        {chips.length > 1 && (
          <button type="button" className="text-[13px] text-accent hover:underline" data-testid="map-clear" onClick={() => setFilters({})}>
            {t('map.clearFilters')}
          </button>
        )}
      </div>
      {canWritePolicies(roles) && policies.length > 0 && (filters.asn || (filters.country && filters.country !== 'INTERNAL')) && (
        <div className="mb-4">
          <GeoBlockAction
            key={`${filters.country ?? ''}|${filters.asn ?? ''}`}
            country={filters.asn ? undefined : filters.country}
            asn={filters.asn ? Number(filters.asn) : undefined}
            label={filters.asn ? `AS${filters.asn}` : regionName(filters.country!)}
            policies={policies}
            defaultPolicy={filters.policy_id}
          />
        </div>
      )}

      <section className="panel mb-5" data-testid="map-basemap-pending">
        <div className="flex items-start gap-3 px-4 py-4 text-[13px]">
          <MapPinOff className="mt-0.5 h-4 w-4 shrink-0 text-muted" aria-hidden />
          <div>
            <p className="font-medium text-ink">{t('map.basemapPending.title')}</p>
            <p className="mt-1 text-muted">{t('map.basemapPending.body')}</p>
          </div>
        </div>
      </section>

      <section className="panel mb-5" data-testid="map-timeline">
        <SectionTitle aside={t('map.approximate')}>{t('map.timeline')}</SectionTitle>
        <div className="px-3 pb-2 pt-1">
          {d && total > 0 ? <StrataChart series={d.timeline} stepSeconds={stepSeconds(d.timeline)} /> : <Empty>{empty}</Empty>}
        </div>
      </section>

      <div className="grid gap-5 xl:grid-cols-2">
        <RankPanel
          testId="map-countries"
          title={t('map.countries')}
          aside={t('map.columns')}
          rows={d?.countries ?? []}
          label={(r) => regionName(r.key)}
          sub={(r) => attackName(r.top_attack_type)}
          active={filters.country}
          onPick={(r) => setFilter('country', r.key)}
          empty={empty}
          locale={locale}
        />
        <RankPanel
          testId="map-cells"
          title={t('map.cells')}
          aside={t('map.cellsNote')}
          rows={d?.cells ?? []}
          label={(r) => r.label || t('map.unknownCity')}
          sub={(r) => (r.lat !== undefined && r.lon !== undefined ? `${r.key} · ${r.lat.toFixed(2)}, ${r.lon.toFixed(2)}` : r.key)}
          empty={empty}
          locale={locale}
        />
        <RankPanel
          testId="map-asns"
          title={t('map.asns')}
          aside={t('map.columns')}
          rows={d?.asns ?? []}
          label={(r) => (r.key === '0' ? t('map.unknownAsn') : `AS${r.key}`)}
          sub={(r) => r.label || undefined}
          active={filters.asn}
          onPick={(r) => (r.key === '0' ? undefined : setFilter('asn', r.key))}
          empty={empty}
          locale={locale}
        />
        <RankPanel
          testId="map-attack-types"
          title={t('map.attackTypes')}
          aside={t('map.columns')}
          rows={d?.types ?? []}
          label={(r) => attackName(r.key)}
          active={filters.attack_type}
          onPick={(r) => setFilter('attack_type', r.key)}
          empty={empty}
          locale={locale}
        />
      </div>

      <section className="mt-5" data-testid="map-events">
        <SectionTitle aside={t('map.eventsNote')}>{t('map.events')}</SectionTitle>
        {events.error && <ErrorBanner message={t('map.eventsError', { error: events.error })} />}
        <EventsTable
          events={events.list}
          isLoading={eventsLoading}
          totalMatched={events.total}
          offset={eventPage * EVENTS_PAGE}
          hasNextPage={!!events.next}
          hasPrevPage={eventPage > 0}
          onNextPage={() => {
            if (!events.next) return;
            const tokens = eventPage + 1 < eventPages.length ? eventPages : [...eventPages, events.next];
            setEventPages(tokens);
            setEventPage(eventPage + 1);
            void loadEvents(eventPage + 1, tokens);
          }}
          onPrevPage={() => {
            if (eventPage === 0) return;
            setEventPage(eventPage - 1);
            void loadEvents(eventPage - 1, eventPages);
          }}
        />
      </section>

      <p className="mt-4 text-xs text-faint" data-testid="map-status">
        {updated && t('overview.updated', { when: updated.toLocaleTimeString(locale) })}
        {live && span ? ` · ${stream.connected ? t('map.liveOn') : stream.error ? t('map.liveError', { error: stream.error }) : t('map.liveConnecting')}` : ''}
        {!span && ` · ${t('map.liveUnavailable')}`}
      </p>
    </AppShell>
  );
};
