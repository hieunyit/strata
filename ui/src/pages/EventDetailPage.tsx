import React, { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { ChevronLeft, SearchX } from 'lucide-react';
import { AppShell } from '../components/layout/AppShell';
import { ErrorBanner, VerdictBadge, relativeTime } from '../components/ui';
import { EventTrace, CopyButton } from '../components/events/EventTrace';
import { apiClient, ApiError, GetEventResponse, isEventsUnavailable } from '../api/client';
import { href } from '../router';
import { buildCurlFromEvent } from '../lib/curl';
import { FalsePositive } from '../components/events/FalsePositive';
import { EventInvestigation } from '../components/events/EventInvestigation';
import { ExceptionDraft } from '../components/events/ExceptionDraft';

type State =
  | { kind: 'loading' }
  | { kind: 'found'; data: GetEventResponse }
  | { kind: 'missing' }
  | { kind: 'failed'; apiMessage?: string };

// One event, opened from the table, the top bar's Block ID lookup or a
// link (#/events/STR-...): the helpdesk's page.
export const EventDetailPage: React.FC<{ blockId: string }> = ({ blockId }) => {
  const { t, i18n } = useTranslation();
  const [reload, setReload] = useState(0);
  const [state, setState] = useState<State>({ kind: 'loading' });
  const id = blockId.trim().toUpperCase();

  useEffect(() => {
    let alive = true;
    setState({ kind: 'loading' });
    apiClient
      .getEvent(id)
      .then((data) => alive && setState({ kind: 'found', data }))
      .catch((err: unknown) => {
        if (!alive) return;
        if (err instanceof ApiError && err.code === 404) setState({ kind: 'missing' });
        else if (isEventsUnavailable(err)) setState({ kind: 'failed', apiMessage: t('errors.eventsUnavailable') });
        else if (err instanceof ApiError) setState({ kind: 'failed', apiMessage: err.message });
        else setState({ kind: 'failed' });
      });
    return () => {
      alive = false;
    };
  }, [id, reload]);

  const ev = state.kind === 'found' ? state.data.event : undefined;

  return (
    <AppShell active="event" wide>
      <a
        href={href({ page: 'events' })}
        onClick={(e) => {
          if (window.history.length > 1) {
            e.preventDefault();
            window.history.back();
          }
        }}
        className="mb-3 inline-flex items-center gap-1 text-[13px] text-muted hover:text-ink"
        data-testid="back-to-events"
      >
        <ChevronLeft className="w-4 h-4" />
        {t('detail.back')}
      </a>
      <div className="mb-6 flex flex-wrap items-center gap-x-4 gap-y-2">
        <h1 className="font-mono text-[22px] font-medium tracking-tight" data-testid="detail-block-id">
          {id}
        </h1>
        {ev && <VerdictBadge action={ev.action} size="md" />}
        <CopyButton text={id} label={t('detail.copyId')} testId="copy-block-id" />
        {ev && <CopyButton text={buildCurlFromEvent(ev)} label={t('detail.copyCurl', 'Copy as cURL')} testId="copy-curl-btn" />}
        {ev && <span className="text-[13px] text-muted">{relativeTime(ev.timestamp, i18n.language)}</span>}
      </div>

      {state.kind === 'loading' && <p className="text-[13px] text-muted">{t('detail.loading')}</p>}
      {state.kind === 'failed' && <ErrorBanner message={state.apiMessage !== undefined ? t('errors.blockIdLookup', { error: state.apiMessage }) : t('errors.blockIdConnection', { id })} testId="error-banner" />}
      {state.kind === 'missing' && (
        <div className="panel px-6 py-10 text-center" data-testid="event-missing">
          <SearchX className="mx-auto mb-3 w-8 h-8 text-faint" />
          <p className="text-[15px] font-medium">{t('errors.blockIdNotFound', { id })}</p>
          <p className="mt-1 text-[13px] text-muted max-w-[60ch] mx-auto">{t('detail.missingHelp')}</p>
        </div>
      )}
      {state.kind === 'found' && <FalsePositive key={`classification:${state.data.event.block_id}`} event={state.data.event} onReload={() => setReload((n) => n + 1)} />}
      {state.kind === 'found' && <ExceptionDraft key={state.data.event.block_id} event={state.data.event} rules={state.data.rules} />}
      {state.kind === 'found' && <EventInvestigation key={`investigation:${id}`} event={state.data.event} />}
      {state.kind === 'found' && <EventTrace event={state.data.event} rules={state.data.rules} />}
    </AppShell>
  );
};
