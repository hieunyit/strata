import React, { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Download, Pause, Play, RefreshCw } from 'lucide-react';
import { AppShell } from '../components/layout/AppShell';
import { PageHeader, ErrorBanner } from '../components/ui';
import { EventFilterBar, EventFilters, emptyFilters } from '../components/events/EventFilterBar';
import { EventsTable } from '../components/events/EventsTable';
import { apiClient, Event, SearchEventsRequest, ApiError } from '../api/client';
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
  const [filters, setFilters] = useState<EventFilters>(() => filtersFromQuery(route?.query));
  const [events, setEvents] = useState<Event[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [live, setLive] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [tokens, setTokens] = useState<string[]>(['']);
  const [pageIndex, setPageIndex] = useState(0);
  const [next, setNext] = useState<string | undefined>();

  const fetchEvents = useCallback(
    async (background = false) => {
      if (background) setRefreshing(true);
      else setLoading(true);
      try {
        const res = await apiClient.searchEvents({ ...searchRequest(filters), page_token: tokens[pageIndex] || undefined });
        setEvents(res.events || []);
        setTotal(res.total_matched || 0);
        setNext(res.next_page_token);
        setError(null);
      } catch (err) {
        setError(err instanceof ApiError ? `${err.message} (HTTP ${err.code})` : t('errors.apiUnreachable'));
      } finally {
        setLoading(false);
        setRefreshing(false);
      }
    },
    [filters, tokens, pageIndex, t],
  );

  useEffect(() => {
    void fetchEvents();
  }, [fetchEvents]);

  // Only the first page follows new events; on later pages rows would
  // shift under the reader.
  useEffect(() => {
    if (!live || pageIndex > 0) return;
    const id = setInterval(() => void fetchEvents(true), REFRESH_MS);
    return () => clearInterval(id);
  }, [live, pageIndex, fetchEvents]);

  const apply = (f: EventFilters) => {
    setFilters(f);
    setTokens(['']);
    setPageIndex(0);
    const query: Record<string, string> = {};
    for (const [k, v] of Object.entries(f)) if (v && !(k === 'range' && v === '24h')) query[k] = v;
    replaceQuery({ page: 'events', query });
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
            <button type="button" className="btn" data-testid="auto-refresh-toggle-btn" onClick={() => setLive(!live)} aria-pressed={!live}>
              {live ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
              {live ? t('common.pause') : t('common.resume')}
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
      <EventsTable
        events={events}
        isLoading={loading}
        totalMatched={total}
        offset={pageIndex * PAGE_SIZE}
        hasNextPage={!!next}
        hasPrevPage={pageIndex > 0}
        onNextPage={() => {
          if (!next) return;
          if (pageIndex + 1 >= tokens.length) setTokens([...tokens, next]);
          setPageIndex(pageIndex + 1);
        }}
        onPrevPage={() => pageIndex > 0 && setPageIndex(pageIndex - 1)}
      />
    </AppShell>
  );
};
