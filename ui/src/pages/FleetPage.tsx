import React from 'react';
import { useTranslation } from 'react-i18next';
import { Download } from 'lucide-react';
import { apiClient, FleetNode, Group, Rollout } from '../api/client';
import { usePolling } from '../usePolling';
import { useAuth } from '../context/AuthContext';
import { downloadCsv, csvDate } from '../lib/csv';
import { PageShell, ErrorBanner, formatTime } from './PageShell';

type Status = 'online' | 'offline' | 'revoked';

const statusOf = (n: FleetNode): Status => (n.revoked ? 'revoked' : n.online ? 'online' : 'offline');

const dot: Record<Status, string> = {
  online: 'bg-emerald-500',
  offline: 'bg-slate-400',
  revoked: 'bg-rose-500',
};

// Bundle states of a node (and of a node in a rollout).
const stateStyle: Record<string, string> = {
  ACTIVE: 'bg-emerald-100 text-emerald-800 dark:bg-emerald-900/40 dark:text-emerald-300',
  VERIFIED: 'bg-sky-100 text-sky-800 dark:bg-sky-900/40 dark:text-sky-300',
  DOWNLOADING: 'bg-amber-100 text-amber-800 dark:bg-amber-900/40 dark:text-amber-300',
  NOTIFIED: 'bg-amber-50 text-amber-700 dark:bg-amber-900/20 dark:text-amber-300',
  PENDING: 'bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-300',
  FAILED: 'bg-rose-100 text-rose-800 dark:bg-rose-900/40 dark:text-rose-300',
  // rollout states
  RUNNING: 'bg-sky-100 text-sky-800 dark:bg-sky-900/40 dark:text-sky-300',
  PAUSED: 'bg-amber-100 text-amber-800 dark:bg-amber-900/40 dark:text-amber-300',
  DONE: 'bg-emerald-100 text-emerald-800 dark:bg-emerald-900/40 dark:text-emerald-300',
};

const StateBadge: React.FC<{ state?: string; testId?: string }> = ({ state, testId }) => {
  const { t } = useTranslation();
  const s = (state || 'NONE').toUpperCase();
  return (
    <span data-testid={testId} data-state={s}
      className={`inline-block px-2 py-0.5 rounded text-xs font-medium ${stateStyle[s] ?? 'bg-slate-100 text-slate-500 dark:bg-slate-800'}`}>
      {t(`fleet.bundleState.${s}`, { defaultValue: s })}
    </span>
  );
};

// The rollout shown: the newest one still moving (running, paused, or
// stopped on a failure); none when the last one is done or aborted.
const ACTIVE_ROLLOUT = ['RUNNING', 'PAUSED', 'FAILED'];

interface FleetData {
  nodes: FleetNode[];
  groups: Group[];
  rollout?: Rollout;
}

async function load(): Promise<FleetData> {
  const [nodes, groups, rollouts] = await Promise.all([apiClient.listNodes(), apiClient.listGroups(), apiClient.listRollouts()]);
  const current = rollouts.find((r) => ACTIVE_ROLLOUT.includes(r.state ?? ''));
  const rollout = current?.id ? (await apiClient.getRollout(current.id)) ?? current : undefined;
  return { nodes, groups, rollout };
}

const RolloutPanel: React.FC<{ rollout?: Rollout; names: Map<string, string> }> = ({ rollout, names }) => {
  const { t } = useTranslation();
  if (!rollout) {
    return <p className="text-sm text-slate-500 mb-6" data-testid="rollout-none">{t('fleet.rollout.none')}</p>;
  }
  const waves = rollout.waves ?? [];
  const nodes = rollout.nodes ?? [];
  return (
    <section data-testid="rollout" data-state={rollout.state}
      className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-4 mb-6">
      <div className="flex flex-wrap items-baseline gap-x-4 gap-y-1 mb-3">
        <h2 className="font-semibold text-slate-900 dark:text-white">
          {t('fleet.rollout.title', { id: rollout.id, version: rollout.bundle_version })}
        </h2>
        <StateBadge state={rollout.state} testId="rollout-state" />
        <span className="text-sm text-slate-600 dark:text-slate-300" data-testid="rollout-wave">
          {t('fleet.rollout.wave', { current: Math.min((rollout.current_wave ?? 0) + 1, waves.length), total: waves.length })}
        </span>
        {rollout.reason && <span className="text-sm text-rose-600 dark:text-rose-400" data-testid="rollout-reason">{rollout.reason}</span>}
      </div>
      <ol className="space-y-2">
        {waves.map((_, w) => {
          const inWave = nodes.filter((n) => (n.wave ?? 0) === w);
          return (
            <li key={w} data-testid="rollout-wave-row" className="flex flex-wrap items-center gap-2 text-sm">
              <span className={`w-20 shrink-0 ${w === rollout.current_wave ? 'font-semibold text-slate-900 dark:text-white' : 'text-slate-500'}`}>
                {t('fleet.rollout.waveN', { n: w + 1 })}
              </span>
              {inWave.map((n) => (
                <span key={n.node_id} data-testid="rollout-node" data-node={n.node_id} data-state={n.state}
                  className="inline-flex items-center gap-1" title={n.error || undefined}>
                  <span className="text-slate-700 dark:text-slate-200">{names.get(n.node_id ?? '') || n.node_id}</span>
                  <StateBadge state={n.state} />
                </span>
              ))}
            </li>
          );
        })}
      </ol>
    </section>
  );
};

// Nodes by connector group, with versions and the state of their bundle,
// and the rollout in progress (W07-F-01). Read-only for every role:
// changes go through deploys and the rollout API. Refreshed every 3
// seconds, so a node's DOWNLOADING → VERIFIED → ACTIVE shows as it happens.
export const FleetPage: React.FC = () => {
  const { t, i18n } = useTranslation();
  const { isViewer } = useAuth();
  const { data, error, loading } = usePolling(load, 3000);
  const nodes = data?.nodes ?? [];
  const groups = data?.groups ?? [];
  const online = nodes.filter((n) => statusOf(n) === 'online').length;
  const names = new Map(nodes.map((n) => [n.id ?? '', n.hostname || n.id || '']));
  const byGroup = new Map<string, FleetNode[]>();
  for (const n of nodes) {
    const g = n.group_id ?? '';
    byGroup.set(g, [...(byGroup.get(g) ?? []), n]);
  }
  const sections = [
    ...groups.map((g) => ({ id: g.id ?? '', name: g.name || g.id || '' })),
    ...[...byGroup.keys()].filter((id) => !groups.some((g) => g.id === id)).map((id) => ({ id, name: id || t('fleet.noGroup') })),
  ];

  const exportCsv = () => {
    downloadCsv(
      `strata-fleet-${csvDate()}.csv`,
      ['Node ID', 'Hostname', 'Group', 'Status', 'NGINX', 'Module', 'Bundle', 'Bundle state', 'Last seen', 'Cert expires'],
      nodes.map((n) => [
        n.id ?? '', n.hostname ?? '', n.group_id ?? '', statusOf(n),
        n.proxy_version ?? '', n.module_version ?? '',
        n.bundle_version ? `v${n.bundle_version}` : '', n.bundle_state ?? '',
        n.last_seen_time ?? '', n.cert_expire_time ?? '',
      ]),
    );
  };

  return (
    <PageShell active="fleet">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold text-slate-900 dark:text-white">{t('fleet.title')}</h1>
          <p className="text-sm text-slate-500 dark:text-slate-400 mb-2">{t('fleet.subtitle')}</p>
        </div>
        {!isViewer && nodes.length > 0 && (
          <button
            type="button"
            data-testid="export-csv-btn"
            onClick={exportCsv}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-700 transition-colors"
          >
            <Download className="w-3.5 h-3.5" />
            <span>{t('common.exportCsv')}</span>
          </button>
        )}
      </div>
      <p className="text-sm text-slate-700 dark:text-slate-200 mb-6" data-testid="fleet-summary">
        {t('fleet.summary', { online, total: nodes.length, groups: groups.length })}
      </p>
      <ErrorBanner message={error && t('common.refreshError', { error })} />
      {!loading && <RolloutPanel rollout={data?.rollout} names={names} />}
      {loading && <p className="text-sm text-slate-500">{t('fleet.loading')}</p>}
      {!loading && nodes.length === 0 && (
        <p className="text-sm text-slate-500" data-testid="nodes-empty">{t('fleet.empty')}</p>
      )}
      {sections.map((g) => {
        const members = byGroup.get(g.id) ?? [];
        return (
          <section key={g.id} data-testid="group" data-group={g.id} className="mb-6">
            <h2 className="text-sm font-semibold text-slate-700 dark:text-slate-200 mb-2">
              {g.name} <span className="font-normal text-slate-500">· {t('fleet.groupCount', { count: members.length })}</span>
            </h2>
            <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl overflow-x-auto">
              <table className="w-full text-sm" data-testid="nodes-table">
                <thead className="bg-slate-50 dark:bg-slate-800/60 text-left text-xs uppercase text-slate-500">
                  <tr>
                    <th className="px-4 py-2">{t('fleet.col.status')}</th>
                    <th className="px-4 py-2">{t('fleet.col.node')}</th>
                    <th className="px-4 py-2">{t('fleet.col.nginx')}</th>
                    <th className="px-4 py-2">{t('fleet.col.module')}</th>
                    <th className="px-4 py-2">{t('fleet.col.bundle')}</th>
                    <th className="px-4 py-2">{t('fleet.col.lastSeen')}</th>
                    <th className="px-4 py-2">{t('fleet.col.cert')}</th>
                  </tr>
                </thead>
                <tbody>
                  {members.length === 0 && (
                    <tr><td colSpan={7} className="px-4 py-4 text-center text-slate-500">{t('fleet.groupEmpty')}</td></tr>
                  )}
                  {members.map((n) => {
                    const s = statusOf(n);
                    return (
                      <tr key={n.id} data-testid="node-row" data-node={n.id} data-status={s} className="border-t border-slate-100 dark:border-slate-800">
                        <td className="px-4 py-2 whitespace-nowrap">
                          <span className={`inline-block w-2 h-2 rounded-full mr-2 ${dot[s]}`} />
                          <span data-testid="node-status">{t(`fleet.status.${s}`)}</span>
                        </td>
                        <td className="px-4 py-2">
                          <div className="font-medium text-slate-900 dark:text-white">{n.hostname || n.id}</div>
                          <div className="text-xs text-slate-500 font-mono">{n.id}</div>
                        </td>
                        <td className="px-4 py-2 text-slate-600 dark:text-slate-300" data-testid="node-nginx">{n.proxy_version || '—'}</td>
                        <td className="px-4 py-2 text-slate-600 dark:text-slate-300" data-testid="node-module">{n.module_version || '—'}</td>
                        <td className="px-4 py-2 whitespace-nowrap">
                          <span className="text-slate-700 dark:text-slate-200 mr-2" data-testid="node-bundle">
                            {n.bundle_version ? `v${n.bundle_version}` : '—'}
                          </span>
                          {n.bundle_version && <StateBadge state={n.bundle_state} testId="node-bundle-state" />}
                        </td>
                        <td className="px-4 py-2 text-slate-500 whitespace-nowrap">{formatTime(n.last_seen_time, i18n.language, t('common.never'))}</td>
                        <td className="px-4 py-2 text-slate-500 whitespace-nowrap">{formatTime(n.cert_expire_time, i18n.language, t('common.never'))}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </section>
        );
      })}
    </PageShell>
  );
};
