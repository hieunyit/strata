import React from 'react';
import { useTranslation } from 'react-i18next';
import { ChevronLeft, ChevronRight } from 'lucide-react';
import { Event } from '../../api/client';
import { useAuth } from '../../context/AuthContext';
import { VerdictBadge, MethodBadge, formatCount } from '../ui';
import { href } from '../../router';

interface EventsTableProps {
  events: Event[];
  isLoading: boolean;
  totalMatched: number;
  /** default: open the event's page */
  onSelectEvent?: (event: Event) => void;
  onNextPage?: () => void;
  onPrevPage?: () => void;
  hasNextPage?: boolean;
  hasPrevPage?: boolean;
  /** first row's position, for "21–40 of 132" */
  offset?: number;
}

function when(iso: string, locale: string): { time: string; date: string } {
  const d = new Date(iso);
  return {
    time: d.toLocaleTimeString(locale, { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
    date: d.toLocaleDateString(locale, { month: 'short', day: 'numeric' }),
  };
}

export const EventsTable: React.FC<EventsTableProps> = ({
  events,
  isLoading,
  totalMatched,
  onSelectEvent,
  onNextPage,
  onPrevPage,
  hasNextPage = false,
  hasPrevPage = false,
  offset = 0,
}) => {
  const { t, i18n } = useTranslation();
  const { maskIp } = useAuth();
  const locale = i18n.language;
  const open = (e: Event) => (onSelectEvent ? onSelectEvent(e) : (window.location.hash = href({ page: 'event', blockId: e.block_id })));

  return (
    <div className="panel overflow-hidden">
      <div className="overflow-x-auto">
        <table className="w-full text-[13px] border-collapse">
          <thead>
            <tr className="border-b border-line bg-sunken/40">
              <th className="th">{t('events.table.timestamp')}</th>
              <th className="th">{t('events.table.blockId')}</th>
              <th className="th">{t('events.table.action')}</th>
              <th className="th">{t('events.table.request')}</th>
              <th className="th">{t('events.table.clientIp')}</th>
              <th className="th">{t('events.table.matchedRules')}</th>
              <th className="th text-right">{t('events.table.score')}</th>
            </tr>
          </thead>
          <tbody>
            {isLoading ? (
              <tr>
                <td colSpan={7} className="py-14 text-center text-muted">{t('events.table.loading')}</td>
              </tr>
            ) : events.length === 0 ? (
              <tr>
                <td colSpan={7} className="py-14 text-center text-muted" data-testid="events-empty">{t('events.table.empty')}</td>
              </tr>
            ) : (
              events.map((evt) => {
                const w = when(evt.timestamp, locale);
                return (
                  <tr
                    key={evt.block_id}
                    onClick={() => open(evt)}
                    className="border-b border-line last:border-0 hover:bg-sunken/60 cursor-pointer transition-colors"
                    data-testid="event-row"
                    data-block-id={evt.block_id}
                  >
                    <td className="td whitespace-nowrap">
                      <div className="tabular-nums font-medium">{w.time}</div>
                      <div className="text-[11px] text-faint">{w.date}</div>
                    </td>
                    <td className="td whitespace-nowrap">
                      <a
                        href={href({ page: 'event', blockId: evt.block_id })}
                        onClick={(e) => {
                          e.stopPropagation();
                          if (onSelectEvent) {
                            e.preventDefault();
                            onSelectEvent(evt);
                          }
                        }}
                        className="font-mono font-bold text-cyan-400 hover:text-cyan-300 hover:underline tracking-tight"
                      >
                        {evt.block_id}
                      </a>
                    </td>
                    <td className="td">
                      <VerdictBadge action={evt.action} />
                    </td>
                    <td className="td max-w-[28rem]">
                      <div className="flex items-center gap-2 min-w-0">
                        <MethodBadge method={evt.http_method} />
                        <span className="font-mono text-[13px] truncate font-medium text-ink" title={`${evt.http_host}${evt.http_path}`}>
                          {evt.http_path}
                        </span>
                      </div>
                      <div className="pl-14 text-xs text-faint truncate flex items-center gap-1.5 mt-0.5">
                        <span>{evt.http_host}</span>
                        {evt.policy_id && (
                          <>
                            <span className="text-line">•</span>
                            <span className="text-muted font-mono">{evt.policy_id}</span>
                          </>
                        )}
                      </div>
                    </td>
                    <td className="td font-mono whitespace-nowrap text-xs" data-testid="table-client-ip">
                      {maskIp(evt.client_ip)}
                    </td>
                    <td className="td whitespace-nowrap">
                      {evt.matched_rules && evt.matched_rules.length > 0 ? (
                        <span className="font-mono text-xs">
                          <span className="px-1.5 py-0.5 rounded bg-sunken border border-line text-ink font-medium">
                            {evt.matched_rules[0]}
                          </span>
                          {evt.matched_rules.length > 1 && (
                            <span className="ml-1 text-xs text-faint">
                              +{evt.matched_rules.length - 1}
                            </span>
                          )}
                        </span>
                      ) : (
                        <span className="text-faint">—</span>
                      )}
                    </td>
                    <td className="td text-right tabular-nums">
                      {evt.score_anomaly && evt.score_anomaly > 0 ? (
                        <span
                          className={`inline-block px-2 py-0.5 rounded-full font-mono text-xs font-bold border ${
                            evt.score_anomaly >= 20
                              ? 'text-rose-400 bg-rose-500/15 border-rose-500/30 shadow-[0_0_8px_rgba(244,63,94,0.2)]'
                              : evt.score_anomaly >= 10
                              ? 'text-amber-400 bg-amber-500/15 border-amber-500/30 shadow-[0_0_8px_rgba(245,158,11,0.2)]'
                              : 'text-cyan-400 bg-cyan-500/15 border-cyan-500/30'
                          }`}
                        >
                          {evt.score_anomaly}
                        </span>
                      ) : (
                        <span className="font-mono text-faint">0</span>
                      )}
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      <div className="flex items-center justify-between gap-3 border-t border-line px-4 py-2.5 text-xs text-muted">
        <div data-testid="events-total">
          {events.length > 0
            ? t('events.pagination.range', {
                from: formatCount(offset + 1, locale),
                to: formatCount(offset + events.length, locale),
                total: formatCount(totalMatched, locale),
              })
            : t('events.pagination.totalMatched', { count: totalMatched })}
        </div>
        <div className="flex items-center gap-2">
          <button type="button" data-testid="prev-page-btn" disabled={!hasPrevPage} onClick={onPrevPage} className="btn h-7 px-2">
            <ChevronLeft className="w-3.5 h-3.5" />
            {t('events.pagination.prev')}
          </button>
          <button type="button" data-testid="next-page-btn" disabled={!hasNextPage} onClick={onNextPage} className="btn h-7 px-2">
            {t('events.pagination.next')}
            <ChevronRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>
    </div>
  );
};
