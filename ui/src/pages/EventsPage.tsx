import React, { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Download, Pause, Play, RefreshCw } from 'lucide-react';
import { AppShell } from '../components/layout/AppShell';
import { PageHeader, ErrorBanner } from '../components/ui';
import { EventFilterBar, EventFilters, emptyFilters } from '../components/events/EventFilterBar';
import { InvestigationSearchPanel } from '../components/events/InvestigationSearchPanel';
import { EventsTable } from '../components/events/EventsTable';
import { apiClient, Event, SearchEventsRequest, ApiError, isEventsUnavailable } from '../api/client';
import { useAuth } from '../context/AuthContext';
import { downloadCsv, csvDate } from '../lib/csv';
import { eventRanges, isRange, windowOf } from '../lib/timeRange';
import { Route, replaceQuery } from '../router';

const PAGE_SIZE = 25;
const REFRESH_MS = 10_000;

export function filtersFromQuery(q: Record<string, string> | undefined): EventFilters {
  const f = { ...emptyFilters };
  if (!q) return f;
  if (isRange(q.range, eventRanges)) f.range = q.range;
  for (const k of ['action', 'client_ip', 'rule_id', 'http_method', 'policy_id', 'node_id'] as const) {
    if (q[k]) f[k] = q[k];
  }
  return f;
}

export function searchRequest(f: EventFilters): SearchEventsRequest {
  return {
    ...windowOf(f.range),
    action: (f.action || undefined) as SearchEventsRequest['action'],
    client_ip: f.client_ip || undefined,
    rule_id: f.rule_id ? Number(f.rule_id) : undefined,
    http_method: f.http_method || undefined,
    policy_id: f.policy_id || undefined,
    node_id: f.node_id || undefined,
    page_size: PAGE_SIZE,
  };
}

export const EventsPage: React.FC<{ route?: Route }> = ({ route }) => {
  const { t } = useTranslation();
  const { maskIp } = useAuth();
 const [savedId,setSavedId]=useState(route?.query?.saved);
 useEffect(()=>{setSavedId(route?.query?.saved);setTokens(['']);setPageIndex(0);},[route?.query?.saved]);
  const [filters, setFilters] = useState<EventFilters>(() => filtersFromQuery(route?.query));
  const [events, setEvents] = useState<Event[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [live, setLive] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const initialPage = route?.query?.page ? Math.max(0, parseInt(route.query.page, 10)) : 0;
  const [tokens, setTokens] = useState<string[]>(['']);
  const [pageIndex, setPageIndex] = useState(initialPage);
  const [next, setNext] = useState<string | undefined>();

  useEffect(() => {
    const qf = filtersFromQuery(route?.query);
    setFilters(qf);
    const p = route?.query?.page ? Math.max(0, parseInt(route.query.page, 10)) : 0;
    setPageIndex(p);
  }, [route?.query]);

  const updateRoute = (f: EventFilters, p: number) => {
    const query: Record<string, string> = {};
    for (const [k, v] of Object.entries(f)) if (v && !(k === 'range' && v === '24h')) query[k] = v;
    if (p > 0) query.page = String(p);
    replaceQuery({ page: 'events', query });
  };

  const fetchEvents = useCallback(
    async (background = false) => {
      if (background) setRefreshing(true);
      else setLoading(true);
      try {
        const res = savedId ? await apiClient.searchSavedEvents(savedId,tokens[pageIndex]) : await apiClient.searchEvents({ ...searchRequest(filters), page_token: tokens[pageIndex] || undefined });
        setEvents(res.events || []);
        setTotal(res.total_matched || 0);
        setNext(res.next_page_token);
        setError(null);
      } catch (err) {
        if (isEventsUnavailable(err)) {
          // not "no events": the list is unknown (CP-A08)
          setEvents([]);
          setTotal(0);
          setError(t('errors.eventsUnavailable'));
          return;
        }
        setError(err instanceof ApiError ? `${err.message} (HTTP ${err.code})` : t('errors.apiUnreachable'));
      } finally {
        setLoading(false);
        setRefreshing(false);
      }
    },
    [filters, tokens, pageIndex, t, savedId],
  );

  useEffect(() => {
    void fetchEvents();
  }, [fetchEvents]);

  // Only the first page follows new events; on later pages rows would
  // shift under the reader.
  useEffect(() => {
    if (!live || pageIndex > 0 || savedId) return;
    const id = setInterval(() => void fetchEvents(true), REFRESH_MS);
    return () => clearInterval(id);
  }, [live, pageIndex, fetchEvents, savedId]);

  const apply = (f: EventFilters) => {
 setSavedId(undefined);
    setFilters(f);
    setTokens(['']);
    setPageIndex(0);
    updateRoute(f, 0);
  };

  // Export CSV: what the table shows. A viewer gets the client IP masked
  // (by the API, and again here) and no input snippet.
  const exportCsv = () => {
    if (events.length === 0) return;
    downloadCsv(
      `strata-events-${csvDate()}.csv`,
      ['Block ID', 'Timestamp', 'Action', 'Policy', 'Method', 'Host', 'Path', 'Client IP', 'Rules', 'Anomaly Score'],
      events.map((e) => [
        e.block_id ?? '', e.timestamp ?? '', e.action ?? '', e.policy_id ?? '', e.http_method ?? '', e.http_host ?? '',
        e.http_path ?? '', maskIp(e.client_ip ?? ''), (e.matched_rules || []).join(';'), e.score_anomaly ?? 0,
      ]),
    );
  };

  return (
    <AppShell active="events" wide>
      <PageHeader
        title={t('events.title')}
        description={t('events.subtitle')}
        actions={
          <>
            <button
              type="button"
              className={`btn ${pageIndex > 0 ? 'border-dashed text-muted' : live ? 'text-ok' : ''}`}
              data-testid="auto-refresh-toggle-btn"
              onClick={() => setLive(!live)}
 disabled={!!savedId}
              aria-pressed={!live}
              title={pageIndex > 0 ? t('events.pausedPageTooltip', 'Live updates paused on historical pages') : undefined}
            >
              {pageIndex > 0 ? (
                <>
                  <Pause className="w-3.5 h-3.5 text-shadow" />
                  <span>{t('events.pausedPage', 'Paused (Page {{page}})', { page: pageIndex + 1 })}</span>
                </>
              ) : (
                <>
                  {live ? <Pause className="w-3.5 h-3.5 text-ok" /> : <Play className="w-3.5 h-3.5" />}
                  <span>{savedId ? t('investigation.fixedWindow') : live ? t('common.pause') : t('common.resume')}</span>
                </>
              )}
            </button>
            <button type="button" className="btn" data-testid="manual-refresh-btn" onClick={() => void fetchEvents(true)} disabled={refreshing}>
              <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
              {t('common.refresh')}
            </button>
            <button type="button" className="btn" data-testid="export-csv-btn" onClick={exportCsv} disabled={events.length === 0}>
              <Download className="w-3.5 h-3.5" />
              {t('common.exportCsv')}
            </button>
          </>
        }
      />
      <ErrorBanner message={error} onClose={() => setError(null)} testId="error-banner" />
      <EventFilterBar initial={filters} onApply={apply} />
 <InvestigationSearchPanel filter={searchRequest(filters)} savedId={savedId} />

      {pageIndex > 0 && (
        <div
          className="panel px-3.5 py-2 mb-3 bg-shadow/10 border-shadow/30 flex items-center justify-between text-[13px]"
          data-testid="live-paused-banner"
        >
          <div className="flex items-center gap-2 text-ink">
            <Pause className="w-4 h-4 text-shadow shrink-0" />
            <span>{t('events.livePausedNotice', 'Live updates are paused on historical pages to prevent shifting rows under your inspection.')}</span>
          </div>
          <button
            type="button"
            className="btn text-xs py-1 h-7 font-medium text-accent hover:underline shrink-0"
            onClick={() => {
              setPageIndex(0);
              if (!savedId) updateRoute(filters, 0);
            }}
            data-testid="return-page-1-btn"
          >
            {t('events.returnToLive', 'Return to Page 1 for Live Stream →')}
          </button>
        </div>
      )}

      <EventsTable
        events={events}
        isLoading={loading}
        totalMatched={total}
        offset={pageIndex * PAGE_SIZE}
        hasNextPage={!!next}
        hasPrevPage={pageIndex > 0}
        onNextPage={() => {
          if (!next) return;
          const nextIdx = pageIndex + 1;
          if (nextIdx >= tokens.length) setTokens([...tokens, next]);
          setPageIndex(nextIdx);
          if (!savedId) updateRoute(filters, nextIdx);
        }}
        onPrevPage={() => {
          if (pageIndex > 0) {
            const prevIdx = pageIndex - 1;
            setPageIndex(prevIdx);
            if (!savedId) updateRoute(filters, prevIdx);
          }
        }}
      />
    </AppShell>
  );
};
