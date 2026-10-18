import React, { useEffect, useState, useMemo, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import { RefreshCw, Download, Search, History, Eye, X } from 'lucide-react';
import { apiClient, AuditEntry, AuditQuery } from '../api/client';
import { AppShell } from '../components/layout/AppShell';
import { PageHeader, ErrorBanner, formatTime, relativeTime } from '../components/ui';
import { useReviewRead } from '../components/policy/useReviewRead';
import { AuditFilters } from '../components/users/AuditFilters';
import { downloadCsv, csvDate } from '../lib/csv';

export const AuditPage: React.FC = () => {
  const { t, i18n } = useTranslation();
  const [query, setQuery] = useState<AuditQuery>({limit:200});
  const read = useReviewRead(JSON.stringify(query), signal => apiClient.searchAuditLogs(query, signal), 0);
  const entries = !read.error && !read.loading ? read.data?.entries ?? [] : [];
  const loading = read.loading;
  const error = read.error ? t('audit.loadError') : null;
  const [search, setSearch] = useState('');
  const [selected, setSelected] = useState<AuditEntry | null>(null);
  const dialog = useRef<HTMLDivElement>(null);
  const opener = useRef<HTMLElement | null>(null);
  useEffect(() => {
    if (!selected || !dialog.current) return;
    const node = dialog.current;
    const buttons = Array.from(node.querySelectorAll<HTMLButtonElement>('button:not(:disabled)'));
    buttons[0]?.focus();
    const keydown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') { e.preventDefault(); setSelected(null); }
      if (e.key === 'Tab' && buttons.length) {
        const target = e.shiftKey ? buttons[buttons.length - 1] : buttons[0];
        const edge = e.shiftKey ? buttons[0] : buttons[buttons.length - 1];
        if (document.activeElement === edge) { e.preventDefault(); target.focus(); }
      }
    };
    node.addEventListener('keydown', keydown);
    const previous = opener.current;
    return () => { node.removeEventListener('keydown', keydown); if (previous?.isConnected) previous.focus(); };
  }, [selected]);
  useEffect(() => { setSelected(null); setSearch(''); }, [query]);

  const filteredEntries = useMemo(() => {
    const q = search.trim().toLowerCase();
    return entries.filter((e) => {
      if (!q) return true;
      return (
        e.actor.toLowerCase().includes(q) ||
        e.resource.toLowerCase().includes(q) ||
        e.action.toLowerCase().includes(q) ||
        (e.request_id && e.request_id.toLowerCase().includes(q))
      );
    });
  }, [entries, search]);

  const exportCsv = () => {
    if (filteredEntries.length === 0) return;
    downloadCsv(
      `strata-audit-${csvDate()}.csv`,
      ['time','actor','channel','action','resource','requestID'].map(key => t(`audit.col.${key}`)),
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
              onClick={() => { setSelected(null); read.refresh(); }}
              disabled={loading}
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
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

      <ErrorBanner message={error} testId="audit-error" />
      <AuditFilters onApply={next => { setQuery(next); read.refresh(); }} />
      {!loading && !error && <p className="text-xs text-muted mb-3" data-testid="audit-result-scope">{t(read.data?.has_more ? 'audit.truncated' : 'audit.newestMatching', {count: entries.length})}</p>}

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
            placeholder={t('audit.searchPlaceholder', 'Search the displayed rows…')}
          />
        </div>

        {search && (
          <button
            type="button"
            className="btn px-2"
            data-testid="audit-reset-filter-btn"
            onClick={() => {
              setSearch('');
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
                      onClick={event => { opener.current = event.currentTarget; setSelected(e); }}
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
          ref={dialog}
          role="dialog"
          aria-labelledby="audit-detail-title"
          aria-modal="true"
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4"
          data-testid="audit-inspect-dialog"
        >
          <div className="panel max-w-3xl w-full max-h-[85vh] flex flex-col p-6 shadow-2xl border border-line bg-surface text-ink animate-in fade-in duration-150">
            <div className="flex items-start justify-between pb-4 border-b border-line">
              <div>
                <h2 id="audit-detail-title" className="text-[16px] font-semibold flex flex-wrap items-center gap-2">
                  <span className="font-mono text-accent">{actionName(selected.action)}</span>
                  <span className="text-muted text-sm font-normal">{t('audit.onResource', {resource:selected.resource})}</span>
                </h2>
                <div className="text-xs text-muted mt-1 flex flex-wrap items-center gap-3">
                  <span>{t('audit.col.actor')}: <strong>{selected.actor}</strong></span>
                  <span>{t('audit.col.channel')}: <strong>{selected.channel}</strong></span>
                  {selected.subject && <span>{t('audit.col.subject')}: <strong>{selected.subject}</strong></span>}
                  {selected.at && <span>{t('audit.col.time')}: {formatTime(selected.at, i18n.language, t('common.never', 'never'))}</span>}
                </div>
              </div>
              <button
                type="button"
                className="btn p-1.5 h-auto text-muted hover:text-ink"
                data-testid="audit-close-inspect-btn"
                aria-label={t('common.close')}
                onClick={() => setSelected(null)}
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="flex-1 overflow-y-auto py-4 grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="min-w-0">
                <h3 className="text-xs font-semibold text-block mb-1.5 uppercase tracking-wider">
                  {t('audit.before', 'Before State')}
                </h3>
                <pre className="p-3 rounded bg-sunken/80 border border-line text-xs font-mono overflow-x-auto max-h-80 whitespace-pre-wrap text-muted">
                  {selected.before != null ? JSON.stringify(selected.before, null, 2) : t('audit.noState')}
                </pre>
              </div>
              <div className="min-w-0">
                <h3 className="text-xs font-semibold text-ok mb-1.5 uppercase tracking-wider">
                  {t('audit.after', 'After State')}
                </h3>
                <pre className="p-3 rounded bg-sunken/80 border border-line text-xs font-mono overflow-x-auto max-h-80 whitespace-pre-wrap text-ink">
                  {selected.after != null ? JSON.stringify(selected.after, null, 2) : t('audit.noState')}
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
