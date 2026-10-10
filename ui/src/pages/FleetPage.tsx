import React from 'react';
import { useTranslation } from 'react-i18next';
import { apiClient, FleetNode, Group } from '../api/client';
import { usePolling } from '../usePolling';
import { PageShell, ErrorBanner, formatTime } from './PageShell';

type Status = 'online' | 'offline' | 'revoked';

const statusOf = (n: FleetNode): Status => (n.revoked ? 'revoked' : n.online ? 'online' : 'offline');

const dot: Record<Status, string> = {
  online: 'bg-emerald-500',
  offline: 'bg-slate-400',
  revoked: 'bg-rose-500',
};

// Nodes and their status (W04-F-01), refreshed every 5 seconds: the
// control plane turns a node offline within 30 s of losing it.
export const FleetPage: React.FC = () => {
  const { t, i18n } = useTranslation();
  const { data, error, loading } = usePolling(
    async (): Promise<{ nodes: FleetNode[]; groups: Group[] }> => {
      const [nodes, groups] = await Promise.all([apiClient.listNodes(), apiClient.listGroups()]);
      return { nodes, groups };
    },
    5000,
  );
  const nodes = data?.nodes ?? [];
  const groups = new Map((data?.groups ?? []).map((g) => [g.id, g.name]));
  const online = nodes.filter((n) => statusOf(n) === 'online').length;

  return (
    <PageShell active="fleet">
      <h1 className="text-xl font-semibold text-slate-900 dark:text-white">{t('fleet.title')}</h1>
      <p className="text-sm text-slate-500 dark:text-slate-400 mb-2">{t('fleet.subtitle')}</p>
      <p className="text-sm text-slate-700 dark:text-slate-200 mb-6" data-testid="fleet-summary">
        {t('fleet.summary', { online, total: nodes.length, groups: data?.groups.length ?? 0 })}
      </p>
      <ErrorBanner message={error && t('common.refreshError', { error })} />
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl overflow-x-auto">
        <table className="w-full text-sm" data-testid="nodes-table">
          <thead className="bg-slate-50 dark:bg-slate-800/60 text-left text-xs uppercase text-slate-500">
            <tr>
              <th className="px-4 py-2">{t('fleet.col.status')}</th>
              <th className="px-4 py-2">{t('fleet.col.node')}</th>
              <th className="px-4 py-2">{t('fleet.col.group')}</th>
              <th className="px-4 py-2">{t('fleet.col.versions')}</th>
              <th className="px-4 py-2">{t('fleet.col.bundle')}</th>
              <th className="px-4 py-2">{t('fleet.col.lastSeen')}</th>
              <th className="px-4 py-2">{t('fleet.col.cert')}</th>
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr><td colSpan={7} className="px-4 py-6 text-center text-slate-500">{t('fleet.loading')}</td></tr>
            )}
            {!loading && nodes.length === 0 && (
              <tr><td colSpan={7} className="px-4 py-6 text-center text-slate-500" data-testid="nodes-empty">{t('fleet.empty')}</td></tr>
            )}
            {nodes.map((n) => {
              const s = statusOf(n);
              return (
                <tr key={n.id} data-testid="node-row" data-status={s} className="border-t border-slate-100 dark:border-slate-800">
                  <td className="px-4 py-2 whitespace-nowrap">
                    <span className={`inline-block w-2 h-2 rounded-full mr-2 ${dot[s]}`} />
                    <span data-testid="node-status">{t(`fleet.status.${s}`)}</span>
                  </td>
                  <td className="px-4 py-2">
                    <div className="font-medium text-slate-900 dark:text-white">{n.hostname || n.id}</div>
                    <div className="text-xs text-slate-500 font-mono">{n.id}</div>
                  </td>
                  <td className="px-4 py-2 text-slate-600 dark:text-slate-300">{groups.get(n.group_id) ?? n.group_id}</td>
                  <td className="px-4 py-2 text-slate-600 dark:text-slate-300">{[n.proxy_version, n.module_version].filter(Boolean).join(' / ') || '—'}</td>
                  <td className="px-4 py-2 text-slate-600 dark:text-slate-300">{n.bundle_version ? `v${n.bundle_version} ${n.bundle_state ?? ''}` : '—'}</td>
                  <td className="px-4 py-2 text-slate-500 whitespace-nowrap">{formatTime(n.last_seen_time, i18n.language, t('common.never'))}</td>
                  <td className="px-4 py-2 text-slate-500 whitespace-nowrap">{formatTime(n.cert_expire_time, i18n.language, t('common.never'))}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </PageShell>
  );
};
