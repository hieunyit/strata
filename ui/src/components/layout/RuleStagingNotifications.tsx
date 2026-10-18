import React, { useCallback, useEffect, useRef, useState } from 'react';
import { Bell, RefreshCw, X } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { apiClient, RuleStagingNoticePage } from '../../api/client';
import { useAuth } from '../../context/AuthContext';
import { href } from '../../router';
import { readPref, writePref } from '../../lib/prefs';

export const RuleStagingNotifications: React.FC = () => {
  const { roles, username } = useAuth();
  const { t, i18n } = useTranslation();
  const allowed = roles.includes('approver') || roles.includes('admin');
  const pref = `staging-seen:${username ?? ''}`;
  const [seen, setSeen] = useState(() => readPref(pref) ?? '');
  const [latestAt, setLatestAt] = useState('');
  const [open, setOpen] = useState(false);
  const [cursor, setCursor] = useState('');
  const [refresh, setRefresh] = useState(0);
  const [page, setPage] = useState<RuleStagingNoticePage>({ notices: [], next_cursor: '' });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const root = useRef<HTMLDivElement>(null);
  const toggle = useRef<HTMLButtonElement>(null);
  const close = useCallback(() => { setOpen(false); setCursor(''); toggle.current?.focus(); }, []);
  const unread = latestAt !== '' && (!Number.isFinite(Date.parse(seen)) || Date.parse(latestAt) > Date.parse(seen));

  useEffect(() => {
    if (!allowed) return;
    const controller = new AbortController();
    let alive = true;
    let inFlight = false;
    const load = async () => {
      if (inFlight || document.visibilityState === 'hidden') return;
      inFlight = true;
      setLoading(true);
      try {
        const response = await apiClient.listRuleStagingNotices(cursor, controller.signal);
        if (!alive) return;
        if (!Array.isArray(response.notices) || typeof response.next_cursor !== 'string') throw new Error('Invalid notice page');
        setPage(response);
        if (!cursor) setLatestAt(response.notices[0]?.created_at ?? '');
        setError(false);
      } catch {
        if (alive && !controller.signal.aborted) setError(true);
      } finally {
        inFlight = false;
        if (alive) setLoading(false);
      }
    };
    void load();
    const tick = window.setInterval(() => { if (!cursor) void load(); }, 15_000);
    const visible = () => { if (!cursor) void load(); };
    document.addEventListener('visibilitychange', visible);
    return () => {
      alive = false;
      controller.abort();
      window.clearInterval(tick);
      document.removeEventListener('visibilitychange', visible);
    };
  }, [allowed, cursor, refresh]);

  useEffect(() => {
    if (!open) return;
    const key = (e: KeyboardEvent) => { if (e.key === 'Escape') close(); };
    const outside = (e: PointerEvent) => { if (!root.current?.contains(e.target as Node)) close(); };
    document.addEventListener('keydown', key);
    document.addEventListener('pointerdown', outside);
    return () => { document.removeEventListener('keydown', key); document.removeEventListener('pointerdown', outside); };
  }, [open, close]);

  if (!allowed) return null;
  return (
    <div ref={root} className="relative">
      <button ref={toggle} type="button" data-testid="staging-notices-toggle" aria-label={t('stagingNotices.title')}
        aria-expanded={open} aria-controls="staging-notice-panel" onClick={() => { if (open) close(); else setOpen(true); }}
        className="relative h-8 w-8 inline-flex items-center justify-center rounded text-muted hover:text-ink hover:bg-sunken">
        <Bell className="w-4 h-4" />
        {error && <span aria-label={t('stagingNotices.unavailable')} className="absolute right-0 top-0 text-xs text-block">!</span>}
        {!error && unread && <span data-testid="staging-unread" role="status" aria-label={t('stagingNotices.unread')} className="absolute right-1 top-1 h-2 w-2 rounded-full bg-block" />}
      </button>
      {open && (
        <section id="staging-notice-panel" aria-label={t('stagingNotices.title')} className="fixed inset-x-3 top-16 z-50 max-w-[calc(100vw-1.5rem)] sm:absolute sm:inset-x-auto sm:right-0 sm:top-10 sm:w-[440px] rounded border border-line bg-surface shadow-xl">
          <div className="flex items-center justify-between gap-2 border-b border-line p-3">
            <h2 className="font-medium text-sm">{t('stagingNotices.title')}</h2>
            <div className="flex gap-2">
              <button type="button" disabled={loading} onClick={() => setRefresh((n) => n + 1)} aria-label={t('stagingNotices.refresh')}><RefreshCw className="h-4 w-4" /></button>
              <button type="button" onClick={close} aria-label={t('common.close')}><X className="h-4 w-4" /></button>
            </div>
          </div>
          <p className="p-3 text-xs text-muted">{t('stagingNotices.explanation')}</p>
          {error && <p role="alert" className="px-3 pb-3 text-sm text-block">{t('stagingNotices.unavailable')}</p>}
          {loading && <p role="status" className="px-3 pb-3 text-sm text-muted">{t('common.loading')}</p>}
          {!loading && !error && page.notices.length === 0 && <p className="px-3 pb-3 text-sm text-muted">{t('stagingNotices.empty')}</p>}
          <ul className="max-h-[50vh] overflow-y-auto divide-y divide-line">
            {page.notices.map((notice) => (
              <li key={notice.id} className="p-3 space-y-1 text-sm">
                <div className="font-medium">{t('stagingNotices.rule', { rule: notice.rule_id })} · {notice.policy_name} v{notice.policy_version}</div>
                <div className="text-xs text-muted">{new Date(notice.created_at).toLocaleString(i18n.language)}</div>
                <div>{t('stagingNotices.rollout', { state: t(`stagingNotices.states.${notice.rollout_state}`) })}</div>
                <div className="text-xs text-muted">{t('stagingNotices.evidence', { reports: notice.reports, matches: notice.matches })}</div>
                <a href={href({ page: 'events', query: { rule_id: String(notice.rule_id), policy_id: notice.policy_name, range: '24h' } })} onClick={close} className="text-accent underline">{t('stagingNotices.viewEvents')}</a>
              </li>
            ))}
          </ul>
          <div className="flex flex-wrap gap-3 border-t border-line p-3 text-xs">
            <button type="button" disabled={!unread || !!cursor || loading || error} onClick={() => { writePref(pref, latestAt); setSeen(latestAt); }}>{t('stagingNotices.markRead')}</button>
            {cursor && <button type="button" onClick={() => setCursor('')}>{t('stagingNotices.latest')}</button>}
            {page.next_cursor && <button type="button" disabled={loading || error} onClick={() => setCursor(page.next_cursor)}>{t('stagingNotices.older')}</button>}
          </div>
        </section>
      )}
    </div>
  );
};
