import React from 'react';
import { useTranslation } from 'react-i18next';
import { ShieldAlert, ShieldCheck, Eye, ExternalLink, ChevronLeft, ChevronRight } from 'lucide-react';
import { Event } from '../../api/client';
import { useAuth } from '../../context/AuthContext';

interface EventsTableProps {
  events: Event[];
  isLoading: boolean;
  totalMatched: number;
  onSelectEvent: (event: Event) => void;
  onNextPage?: () => void;
  onPrevPage?: () => void;
  hasNextPage?: boolean;
  hasPrevPage?: boolean;
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
}) => {
  const { t } = useTranslation();
  const { maskIp } = useAuth();

  const renderActionBadge = (action: string) => {
    switch (action.toLowerCase()) {
      case 'block':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-rose-100 text-rose-800 dark:bg-rose-950/60 dark:text-rose-300 border border-rose-200 dark:border-rose-900">
            <ShieldAlert className="w-3 h-3" />
            <span>{t('events.actions.block')}</span>
          </span>
        );
      case 'shadow':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-100 text-amber-800 dark:bg-amber-950/60 dark:text-amber-300 border border-amber-200 dark:border-amber-900">
            <Eye className="w-3 h-3" />
            <span>{t('events.actions.shadow')}</span>
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-100 text-emerald-800 dark:bg-emerald-950/60 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-900">
            <ShieldCheck className="w-3 h-3" />
            <span>{t('events.actions.allow')}</span>
          </span>
        );
    }
  };

  const getMethodBadgeClass = (method: string) => {
    switch (method.toUpperCase()) {
      case 'GET':
        return 'text-sky-700 bg-sky-50 dark:text-sky-300 dark:bg-sky-950/40 border-sky-200 dark:border-sky-800';
      case 'POST':
        return 'text-emerald-700 bg-emerald-50 dark:text-emerald-300 dark:bg-emerald-950/40 border-emerald-200 dark:border-emerald-800';
      case 'PUT':
      case 'PATCH':
        return 'text-amber-700 bg-amber-50 dark:text-amber-300 dark:bg-amber-950/40 border-amber-200 dark:border-amber-800';
      case 'DELETE':
        return 'text-rose-700 bg-rose-50 dark:text-rose-300 dark:bg-rose-950/40 border-rose-200 dark:border-rose-800';
      default:
        return 'text-slate-700 bg-slate-50 dark:text-slate-300 dark:bg-slate-800 border-slate-200 dark:border-slate-700';
    }
  };

  return (
    <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl shadow-sm overflow-hidden transition-colors">
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs border-collapse">
          <thead>
            <tr className="border-b border-slate-200 dark:border-slate-800 bg-slate-50/75 dark:bg-slate-800/40 text-slate-500 font-semibold uppercase tracking-wider">
              <th className="py-3 px-4">{t('events.table.timestamp')}</th>
              <th className="py-3 px-4">{t('events.table.blockId')}</th>
              <th className="py-3 px-4">{t('events.table.action')}</th>
              <th className="py-3 px-4">{t('events.table.method')}</th>
              <th className="py-3 px-4">{t('events.table.path')}</th>
              <th className="py-3 px-4">{t('events.table.clientIp')}</th>
              <th className="py-3 px-4">{t('events.table.matchedRules')}</th>
              <th className="py-3 px-4 text-center">{t('events.table.score')}</th>
              <th className="py-3 px-4 text-right">{t('events.table.actions')}</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
            {isLoading ? (
              <tr>
                <td colSpan={9} className="py-12 text-center text-slate-400">
                  <div className="flex items-center justify-center gap-2">
                    <div className="w-4 h-4 rounded-full border-2 border-sky-600 border-t-transparent animate-spin" />
                    <span>{t('events.table.loading')}</span>
                  </div>
                </td>
              </tr>
            ) : events.length === 0 ? (
              <tr>
                <td colSpan={9} className="py-12 text-center text-slate-400">
                  {t('events.table.empty')}
                </td>
              </tr>
            ) : (
              events.map((evt) => (
                <tr
                  key={evt.block_id}
                  onClick={() => onSelectEvent(evt)}
                  className="hover:bg-slate-50/80 dark:hover:bg-slate-800/50 cursor-pointer transition-colors"
                  data-testid="event-row"
                  data-block-id={evt.block_id}
                >
                  <td className="py-3 px-4 text-slate-500 whitespace-nowrap">
                    {new Date(evt.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                  </td>
                  <td className="py-3 px-4 font-mono font-medium text-sky-600 dark:text-sky-400 hover:underline whitespace-nowrap">
                    {evt.block_id}
                  </td>
                  <td className="py-3 px-4 whitespace-nowrap">
                    {renderActionBadge(evt.action)}
                  </td>
                  <td className="py-3 px-4 whitespace-nowrap">
                    <span className={`px-2 py-0.5 rounded font-mono font-semibold text-[11px] border ${getMethodBadgeClass(evt.http_method)}`}>
                      {evt.http_method}
                    </span>
                  </td>
                  <td className="py-3 px-4 max-w-xs font-mono text-slate-700 dark:text-slate-300 truncate" title={`${evt.http_host}${evt.http_path}`}>
                    <span className="text-slate-400">{evt.http_host}</span>
                    <span>{evt.http_path}</span>
                  </td>
                  <td className="py-3 px-4 font-mono text-slate-600 dark:text-slate-400 whitespace-nowrap" data-testid="table-client-ip">
                    {maskIp(evt.client_ip)}
                  </td>
                  <td className="py-3 px-4 whitespace-nowrap">
                    {evt.matched_rules && evt.matched_rules.length > 0 ? (
                      <div className="flex items-center gap-1 flex-wrap">
                        {evt.matched_rules.slice(0, 2).map((r) => (
                          <span key={r} className="px-1.5 py-0.5 rounded text-[11px] font-mono bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300">
                            {r}
                          </span>
                        ))}
                        {evt.matched_rules.length > 2 && (
                          <span className="text-[11px] text-slate-400 font-mono">
                            +{evt.matched_rules.length - 2}
                          </span>
                        )}
                      </div>
                    ) : (
                      <span className="text-slate-400">—</span>
                    )}
                  </td>
                  <td className="py-3 px-4 text-center font-mono font-semibold whitespace-nowrap">
                    <span className={evt.score_anomaly && evt.score_anomaly > 0 ? 'text-rose-600 dark:text-rose-400' : 'text-slate-400'}>
                      {evt.score_anomaly ?? 0}
                    </span>
                  </td>
                  <td className="py-3 px-4 text-right whitespace-nowrap">
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        onSelectEvent(evt);
                      }}
                      className="p-1 rounded hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-400 hover:text-sky-600 transition-colors inline-flex items-center gap-1 text-[11px]"
                      title={t('events.table.viewTrace')}
                    >
                      <span>{t('events.table.viewTrace')}</span>
                      <ExternalLink className="w-3.5 h-3.5" />
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination Footer */}
      <div className="py-3 px-4 border-t border-slate-100 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-800/40 flex items-center justify-between text-xs text-slate-500">
        <div>
          {t('events.pagination.totalMatched', { count: totalMatched })}
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            data-testid="prev-page-btn"
            disabled={!hasPrevPage}
            onClick={onPrevPage}
            className="flex items-center gap-1 px-2.5 py-1 rounded bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300 disabled:opacity-40 disabled:cursor-not-allowed hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors shadow-sm"
          >
            <ChevronLeft className="w-3.5 h-3.5" />
            <span>{t('events.pagination.prev')}</span>
          </button>
          <button
            type="button"
            data-testid="next-page-btn"
            disabled={!hasNextPage}
            onClick={onNextPage}
            className="flex items-center gap-1 px-2.5 py-1 rounded bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300 disabled:opacity-40 disabled:cursor-not-allowed hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors shadow-sm"
          >
            <span>{t('events.pagination.next')}</span>
            <ChevronRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>
    </div>
  );
};
