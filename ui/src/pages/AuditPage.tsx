import React, { useEffect, useState, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { RefreshCw, Download, Search, History, Eye, X } from 'lucide-react';
import { apiClient, AuditEntry } from '../api/client';
import { AppShell } from '../components/layout/AppShell';
import { PageHeader, ErrorBanner, formatTime, relativeTime } from '../components/ui';
import { downloadCsv, csvDate } from '../lib/csv';

export const AuditPage: React.FC = () => {
  const { t, i18n } = useTranslation();
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [search, setSearch] = useState('');
  const [actionFilter, setActionFilter] = useState('');

  // Selected entry for inspection drawer
  const [selected, setSelected] = useState<AuditEntry | null>(null);

  const fetchAudit = async (isManual = false) => {
    if (isManual) setRefreshing(true);
    else setLoading(true);
    try {
      const data = await apiClient.listAuditLogs(200);
      setEntries(data || []);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : t('errors.apiUnreachable'));
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    void fetchAudit();
  }, []);

  const filteredEntries = useMemo(() => {
    const q = search.trim().toLowerCase();
    return entries.filter((e) => {
      if (actionFilter && !e.action.includes(actionFilter)) return false;
      if (!q) return true;
      return (
        e.actor.toLowerCase().includes(q) ||
        e.resource.toLowerCase().includes(q) ||
        e.action.toLowerCase().includes(q) ||
        (e.request_id && e.request_id.toLowerCase().includes(q))
      );
    });
  }, [entries, search, actionFilter]);

  const exportCsv = () => {
    if (filteredEntries.length === 0) return;
    downloadCsv(
      `strata-audit-${csvDate()}.csv`,
      ['Timestamp', 'Actor', 'Channel', 'Action', 'Resource', 'Request ID'],
      filteredEntries.map((e) => [
        e.at ?? '',
        e.actor ?? '',
        e.channel ?? '',
        e.action ?? '',
        e.resource ?? '',
        e.request_id ?? '',
      ]),
    );
  };

  const actionName = (action: string) => {
    const parts = action.split('/');
    return parts[parts.length - 1] || action;
  };

  return (
    <AppShell active="audit" wide>
      <PageHeader
        title={t('audit.title', 'Audit Trail')}
        description={t(
          'audit.subtitle',
          'Chronological log of administrative actions, policy releases, and node operations.'
        )}
        actions={
          <>
            <button
              type="button"
              className="btn"
              data-testid="audit-refresh-btn"
              onClick={() => void fetchAudit(true)}
              disabled={refreshing}
            >
              <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
              {t('common.refresh', 'Refresh')}
            </button>
            <button
              type="button"
              className="btn"
              data-testid="audit-export-btn"
              onClick={exportCsv}
              disabled={filteredEntries.length === 0}
            >
              <Download className="w-3.5 h-3.5" />
              {t('common.exportCsv', 'Export CSV')}
            </button>
          </>
        }
      />

      <ErrorBanner message={error} onClose={() => setError(null)} testId="audit-error" />

      {/* Filter bar */}
      <div className="panel p-3 mb-4 flex flex-wrap items-center gap-3 text-[13px]">
        <div className="flex-1 min-w-[15rem] relative">
          <Search className="w-4 h-4 text-muted absolute left-2.5 top-1/2 -translate-y-1/2 pointer-events-none" />
          <input
            type="text"
            className="field pl-8"
            data-testid="audit-search-input"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder={t('audit.searchPlaceholder', 'Filter by actor, resource, or action…')}
          />
        </div>

        <div className="w-48">
          <select
            className="field"
            data-testid="audit-action-filter"
            value={actionFilter}
            onChange={(e) => setActionFilter(e.target.value)}
          >
            <option value="">{t('audit.allActions', 'All Actions')}</option>
            <option value="Policy">Policy Changes</option>
            <option value="RevokeNode">Node Revocations</option>
            <option value="local_users">User Admin</option>
            <option value="local_sessions">Session Events</option>
          </select>
        </div>

        {(search || actionFilter) && (
          <button
            type="button"
            className="btn px-2"
            data-testid="audit-reset-filter-btn"
            onClick={() => {
              setSearch('');
              setActionFilter('');
            }}
          >
            {t('common.reset', 'Reset')}
          </button>
        )}
      </div>

      {/* Table */}
      <div className="panel overflow-x-auto" data-testid="audit-panel">
        <table className="w-full text-[13px]" data-testid="audit-table">
          <thead>
            <tr className="border-b border-line bg-sunken/50">
              <th className="th">{t('audit.col.time', 'Timestamp')}</th>
              <th className="th">{t('audit.col.actor', 'Actor')}</th>
              <th className="th">{t('audit.col.channel', 'Channel')}</th>
              <th className="th">{t('audit.col.action', 'Action')}</th>
              <th className="th">{t('audit.col.resource', 'Resource')}</th>
              <th className="th text-right">{t('audit.col.details', 'Details')}</th>
            </tr>
          </thead>
          <tbody>
            {loading && entries.length === 0 && (
              <tr>
                <td colSpan={6} className="td py-8 text-center text-muted" data-testid="audit-loading">
                  {t('audit.loading', 'Loading audit log…')}
                </td>
              </tr>
            )}
            {!loading && filteredEntries.length === 0 && (
              <tr>
                <td colSpan={6} className="td py-8 text-center text-muted" data-testid="audit-empty">
                  <History className="w-6 h-6 mx-auto mb-2 text-faint" />
                  {t('audit.empty', 'No audit log entries match your filter.')}
                </td>
              </tr>
            )}
            {filteredEntries.map((e, idx) => (
              <tr
                key={idx}
                className="border-b border-line last:border-0 hover:bg-sunken/30 transition-colors"
                data-testid="audit-row"
              >
                <td
                  className="td whitespace-nowrap text-muted"
                  title={e.at ? formatTime(e.at, i18n.language, t('common.never', 'never')) : undefined}
                >
                  {e.at ? relativeTime(e.at, i18n.language) : '—'}
                </td>
                <td className="td whitespace-nowrap font-medium" data-testid="audit-actor">
                  {e.actor}
                </td>
                <td className="td whitespace-nowrap">
                  <span className="font-mono text-xs px-1.5 py-0.5 rounded bg-sunken border border-line text-muted">
                    {e.channel}
                  </span>
                </td>
                <td className="td whitespace-nowrap font-mono text-xs text-ink" data-testid="audit-action">
                  {actionName(e.action)}
                </td>
                <td className="td font-mono text-xs text-muted max-w-xs truncate" title={e.resource}>
                  {e.resource}
                </td>
                <td className="td text-right whitespace-nowrap">
                  {(e.before != null || e.after != null) && (
                    <button
                      type="button"
                      className="btn py-1 px-2 h-7 text-xs"
                      data-testid="audit-inspect-btn"
                      onClick={() => setSelected(e)}
                    >
                      <Eye className="w-3.5 h-3.5" />
                      {t('audit.inspect', 'Diff')}
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Before / After Inspector Modal */}
      {selected && (
        <div
          role="dialog"
          aria-modal="true"
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4"
          data-testid="audit-inspect-dialog"
        >
          <div className="panel max-w-3xl w-full max-h-[85vh] flex flex-col p-6 shadow-2xl border border-line bg-surface text-ink animate-in fade-in duration-150">
            <div className="flex items-start justify-between pb-4 border-b border-line">
              <div>
                <h2 className="text-[16px] font-semibold flex items-center gap-2">
                  <span className="font-mono text-accent">{actionName(selected.action)}</span>
                  <span className="text-muted text-sm font-normal">on {selected.resource}</span>
                </h2>
                <div className="text-xs text-muted mt-1 flex items-center gap-3">
                  <span>Actor: <strong>{selected.actor}</strong></span>
                  <span>Channel: <strong>{selected.channel}</strong></span>
                  {selected.at && <span>Time: {formatTime(selected.at, i18n.language, t('common.never', 'never'))}</span>}
                </div>
              </div>
              <button
                type="button"
                className="btn p-1.5 h-auto text-muted hover:text-ink"
                data-testid="audit-close-inspect-btn"
                onClick={() => setSelected(null)}
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="flex-1 overflow-y-auto py-4 grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <h3 className="text-xs font-semibold text-block mb-1.5 uppercase tracking-wider">
                  {t('audit.before', 'Before State')}
                </h3>
                <pre className="p-3 rounded bg-sunken/80 border border-line text-xs font-mono overflow-x-auto max-h-80 whitespace-pre-wrap text-muted">
                  {selected.before ? JSON.stringify(selected.before, null, 2) : '(none)'}
                </pre>
              </div>
              <div>
                <h3 className="text-xs font-semibold text-ok mb-1.5 uppercase tracking-wider">
                  {t('audit.after', 'After State')}
                </h3>
                <pre className="p-3 rounded bg-sunken/80 border border-line text-xs font-mono overflow-x-auto max-h-80 whitespace-pre-wrap text-ink">
                  {selected.after ? JSON.stringify(selected.after, null, 2) : '(none)'}
                </pre>
              </div>
            </div>

            <div className="pt-3 border-t border-line flex justify-end">
              <button
                type="button"
                className="btn"
                onClick={() => setSelected(null)}
              >
                {t('common.close', 'Close')}
              </button>
            </div>
          </div>
        </div>
      )}
    </AppShell>
  );
};
