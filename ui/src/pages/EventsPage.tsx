import React, { useState, useEffect, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import { Header } from '../components/layout/Header';
import { EventFilterBar } from '../components/events/EventFilterBar';
import { EventsTable } from '../components/events/EventsTable';
import { DecisionTraceModal } from '../components/events/DecisionTraceModal';
import { apiClient, Event, SearchEventsRequest, ApiError } from '../api/client';
import { AlertCircle } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { downloadCsv, csvDate } from '../lib/csv';

export const EventsPage: React.FC<{ initialBlockId?: string }> = ({ initialBlockId }) => {
  const { t } = useTranslation();
  const { maskIp } = useAuth();

  // Query state
  const [filters, setFilters] = useState<SearchEventsRequest>(() => {
    const now = new Date();
    return {
      from: new Date(now.getTime() - 24 * 60 * 60 * 1000).toISOString(),
      to: now.toISOString(),
      page_size: 20,
    };
  });

  const [events, setEvents] = useState<Event[]>([]);
  const [totalMatched, setTotalMatched] = useState<number>(0);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);
  const [isAutoRefresh, setIsAutoRefresh] = useState<boolean>(true);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Pagination tokens history stack
  const [pageTokens, setPageTokens] = useState<string[]>(['']);
  const [currentPageIndex, setCurrentPageIndex] = useState<number>(0);
  const [nextPageToken, setNextPageToken] = useState<string | undefined>(undefined);

  // Decision trace modal state
  const [selectedEvent, setSelectedEvent] = useState<Event | null>(null);
  const [isModalOpen, setIsModalOpen] = useState<boolean>(false);
  const [isModalLoading, setIsModalLoading] = useState<boolean>(false);
  const [isSearchingBlockId, setIsSearchingBlockId] = useState<boolean>(false);

  // Fetch events function
  const fetchEvents = useCallback(async (isBackground = false) => {
    if (isBackground) {
      setIsRefreshing(true);
    } else {
      setIsLoading(true);
    }
    setErrorMessage(null);

    try {
      const activeToken = pageTokens[currentPageIndex] || undefined;
      const res = await apiClient.searchEvents({
        ...filters,
        page_token: activeToken,
      });

      setEvents(res.events || []);
      setTotalMatched(res.total_matched || 0);
      setNextPageToken(res.next_page_token);
    } catch (err: unknown) {
      if (err instanceof ApiError) {
        setErrorMessage(`${err.message} (HTTP ${err.code})`);
      } else {
        setErrorMessage(t('errors.apiUnreachable'));
      }
    } finally {
      setIsLoading(false);
      setIsRefreshing(false);
    }
  }, [filters, pageTokens, currentPageIndex, t]);

  // Initial and reactive fetch
  useEffect(() => {
    fetchEvents();
  }, [fetchEvents]);

  // Auto-refresh timer (every 5 seconds when enabled and not paused)
  useEffect(() => {
    if (!isAutoRefresh) return;
    const interval = setInterval(() => {
      fetchEvents(true);
    }, 5000);
    return () => clearInterval(interval);
  }, [isAutoRefresh, fetchEvents]);

  // Handle global Block ID search from Header
  const handleGlobalBlockIdSearch = async (blockId: string) => {
    setIsSearchingBlockId(true);
    setIsModalLoading(true);
    setIsModalOpen(true);
    setErrorMessage(null);

    try {
      const res = await apiClient.getEvent(blockId);
      setSelectedEvent(res.event);
    } catch (err: unknown) {
      setSelectedEvent(null);
      if (err instanceof ApiError) {
        if (err.code === 404) {
          setErrorMessage(t('errors.blockIdNotFound', { id: blockId }));
        } else {
          setErrorMessage(t('errors.blockIdLookup', { error: err.message }));
        }
      } else {
        setErrorMessage(t('errors.blockIdConnection', { id: blockId }));
      }
    } finally {
      setIsSearchingBlockId(false);
      setIsModalLoading(false);
    }
  };

  // A Block ID in the route (#/events/STR-...), e.g. searched from another page.
  useEffect(() => {
    if (initialBlockId) void handleGlobalBlockIdSearch(initialBlockId);
    // Only when the Block ID changes, not on every render.
  }, [initialBlockId]);

  // Open modal for table row click
  const handleSelectEvent = async (event: Event) => {
    setSelectedEvent(event);
    setIsModalOpen(true);

    // Also fetch full decision trace to ensure violations and details are completely loaded
    try {
      setIsModalLoading(true);
      const res = await apiClient.getEvent(event.block_id);
      setSelectedEvent(res.event);
    } catch {
      // If fetching fails, we still have the event from table
    } finally {
      setIsModalLoading(false);
    }
  };

  // Export CSV: what the table shows. A viewer gets the client IP masked
  // (by the API, and again here) and no input snippet.
  const handleExportCsv = () => {
    if (events.length === 0) return;
    downloadCsv(
      `strata-events-${csvDate()}.csv`,
      ['Block ID', 'Timestamp', 'Action', 'Method', 'Host', 'Path', 'Client IP', 'Rules', 'Anomaly Score'],
      events.map((e) => [
        e.block_id ?? '', e.timestamp ?? '', e.action ?? '', e.http_method ?? '', e.http_host ?? '',
        e.http_path ?? '', maskIp(e.client_ip ?? ''), (e.matched_rules || []).join(';'), e.score_anomaly ?? 0,
      ]),
    );
  };

  // Filter application
  const handleApplyFilters = (newFilters: SearchEventsRequest) => {
    setFilters(newFilters);
    setPageTokens(['']);
    setCurrentPageIndex(0);
  };

  // Next page
  const handleNextPage = () => {
    if (!nextPageToken) return;
    const newTokens = [...pageTokens];
    if (currentPageIndex + 1 >= newTokens.length) {
      newTokens.push(nextPageToken);
    }
    setPageTokens(newTokens);
    setCurrentPageIndex(currentPageIndex + 1);
  };

  // Previous page
  const handlePrevPage = () => {
    if (currentPageIndex > 0) {
      setCurrentPageIndex(currentPageIndex - 1);
    }
  };

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-slate-950 flex flex-col transition-colors">
      <Header
        active="events"
        onSearchBlockId={handleGlobalBlockIdSearch}
        isSearchingBlockId={isSearchingBlockId}
      />

      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Page Title */}
        <div className="mb-6">
          <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-white">
            {t('events.title')}
          </h1>
          <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
            {t('events.subtitle')}
          </p>
        </div>

        {/* Global Error Banner */}
        {errorMessage && (
          <div
            data-testid="error-banner"
            className="mb-6 p-4 rounded-xl bg-rose-50 dark:bg-rose-950/40 border border-rose-200 dark:border-rose-900 text-sm text-rose-800 dark:text-rose-200 flex items-center justify-between shadow-sm animate-in fade-in"
          >
            <div className="flex items-center gap-2.5">
              <AlertCircle className="w-5 h-5 shrink-0 text-rose-600 dark:text-rose-400" />
              <span>{errorMessage}</span>
            </div>
            <button
              onClick={() => setErrorMessage(null)}
              className="text-xs text-rose-500 hover:underline"
            >
              {t('errors.close')}
            </button>
          </div>
        )}

        {/* Filter Bar */}
        <EventFilterBar
          initialFilters={filters}
          onApplyFilters={handleApplyFilters}
          onExportCsv={handleExportCsv}
          isAutoRefresh={isAutoRefresh}
          onToggleAutoRefresh={() => setIsAutoRefresh(!isAutoRefresh)}
          isRefreshing={isRefreshing}
          onManualRefresh={() => fetchEvents(true)}
        />

        {/* Events Table */}
        <EventsTable
          events={events}
          isLoading={isLoading}
          totalMatched={totalMatched}
          onSelectEvent={handleSelectEvent}
          onNextPage={handleNextPage}
          onPrevPage={handlePrevPage}
          hasNextPage={Boolean(nextPageToken)}
          hasPrevPage={currentPageIndex > 0}
        />
      </main>

      {/* Decision Trace Modal */}
      <DecisionTraceModal
        event={selectedEvent}
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        isLoading={isModalLoading}
      />
    </div>
  );
};
