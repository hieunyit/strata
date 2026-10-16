import React, { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Download } from 'lucide-react';
import { apiClient, FleetNode, Group, Rollout } from '../api/client';
import { usePolling } from '../usePolling';
import { downloadCsv, csvDate } from '../lib/csv';
import { PageShell } from './PageShell';
import { PageHeader, ErrorBanner, formatTime, relativeTime } from '../components/ui';
import { useAuth } from '../context/AuthContext';
import { DestructiveConfirmModal } from '../components/layout/DestructiveConfirmModal';

type Status = 'online' | 'offline' | 'revoked';

const statusOf = (n: FleetNode): Status => (n.revoked ? 'revoked' : n.online ? 'online' : 'offline');
// online nodes first, revoked ones last (W11 review: revoked test nodes
// filled the top of the table); the API's order within each status
const rank: Record<Status, number> = { online: 0, offline: 1, revoked: 2 };
export const byStatus = (nodes: FleetNode[]): FleetNode[] =>
  nodes.map((n, i) => ({ n, i })).sort((a, b) => rank[statusOf(a.n)] - rank[statusOf(b.n)] || a.i - b.i).map(({ n }) => n);

const dot: Record<Status, string> = {
  online: 'bg-ok',
  offline: 'bg-faint',
  revoked: 'bg-block',
};

// Bundle states of a node (and of a node in a rollout).
const stateStyle: Record<string, string> = {
  ACTIVE: 'text-ok border-ok/35 bg-ok/10',
  VERIFIED: 'text-accent border-accent/35 bg-accent/10',
  DOWNLOADING: 'text-shadow border-shadow/35 bg-shadow/10',
  NOTIFIED: 'text-shadow border-shadow/25',
  PENDING: 'text-muted border-line',
  FAILED: 'text-block border-block/35 bg-block/10',
  // rollout states
  RUNNING: 'text-accent border-accent/35 bg-accent/10',
  PAUSED: 'text-shadow border-shadow/35 bg-shadow/10',
  DONE: 'text-ok border-ok/35 bg-ok/10',
};

const StateBadge: React.FC<{ state?: string; testId?: string }> = ({ state, testId }) => {
  const { t } = useTranslation();
  const s = (state || 'NONE').toUpperCase();
  return (
    <span data-testid={testId} data-state={s}
      className={`inline-block rounded border px-1.5 py-0.5 text-xs font-medium ${stateStyle[s] ?? 'text-muted border-line'}`}>
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
    return <p className="mb-6 text-[13px] text-muted" data-testid="rollout-none">{t('fleet.rollout.none')}</p>;
  }
  const waves = rollout.waves ?? [];
  const nodes = rollout.nodes ?? [];
  return (
    <section data-testid="rollout" data-state={rollout.state}
      className="panel mb-6 p-4">
      <div className="flex flex-wrap items-baseline gap-x-4 gap-y-1 mb-3">
        <h2 className="text-[15px] font-semibold">
          {t('fleet.rollout.title', { id: rollout.id, version: rollout.bundle_version })}
        </h2>
        <StateBadge state={rollout.state} testId="rollout-state" />
        <span className="text-[13px] text-muted" data-testid="rollout-wave">
          {t('fleet.rollout.wave', { current: Math.min((rollout.current_wave ?? 0) + 1, waves.length), total: waves.length })}
        </span>
        {rollout.reason && <span className="text-[13px] text-block" data-testid="rollout-reason">{rollout.reason}</span>}
      </div>
      <ol className="space-y-2">
        {waves.map((_, w) => {
          const inWave = nodes.filter((n) => (n.wave ?? 0) === w);
          return (
            <li key={w} data-testid="rollout-wave-row" className="flex flex-wrap items-center gap-2 text-[13px]">
              <span className={`w-20 shrink-0 ${w === rollout.current_wave ? 'font-semibold' : 'text-muted'}`}>
                {t('fleet.rollout.waveN', { n: w + 1 })}
              </span>
              {inWave.map((n) => (
                <span key={n.node_id} data-testid="rollout-node" data-node={n.node_id} data-state={n.state}
                  className="inline-flex items-center gap-1" title={n.error || undefined}>
                  <span>{names.get(n.node_id ?? '') || n.node_id}</span>
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
  const { data, error, loading, refresh } = usePolling(load, 3000);
  const { roles } = useAuth();
  const canRevoke = roles.includes('admin');
  const [revokingNode, setRevokingNode] = useState<FleetNode | null>(null);

  const nodes = data?.nodes ?? [];
  const groups = data?.groups ?? [];
  const online = nodes.filter((n) => statusOf(n) === 'online').length;
  const names = new Map(nodes.map((n) => [n.id ?? '', n.hostname || n.id || '']));
  const byGroup = new Map<string, FleetNode[]>();
  for (const n of byStatus(nodes)) {
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
      <PageHeader
        title={t('fleet.title')}
        description={t('fleet.subtitle')}
        actions={
          nodes.length > 0 && (
            <button type="button" data-testid="export-csv-btn" onClick={exportCsv} className="btn">
              <Download className="w-3.5 h-3.5" />
              {t('common.exportCsv')}
            </button>
          )
        }
      />
      <p className="mb-5 text-[13px]" data-testid="fleet-summary">
        {t('fleet.summary', { online, total: nodes.length, groups: groups.length })}
      </p>
      <ErrorBanner message={error && t('common.refreshError', { error })} />
      {!loading && <RolloutPanel rollout={data?.rollout} names={names} />}
      {loading && <p className="text-[13px] text-muted">{t('fleet.loading')}</p>}
      {!loading && nodes.length === 0 && (
        <p className="text-[13px] text-muted" data-testid="nodes-empty">{t('fleet.empty')}</p>
      )}
      {sections.map((g) => {
        const members = byGroup.get(g.id) ?? [];
        return (
          <section key={g.id} data-testid="group" data-group={g.id} className="mb-6">
            <h2 className="mb-2 flex items-baseline gap-2 text-[13px] font-semibold">
              {g.name}
              <span className="font-normal text-muted">{t('fleet.groupCount', { count: members.length })}</span>
            </h2>
            <div className="panel overflow-x-auto">
              <table className="w-full text-[13px]" data-testid="nodes-table">
                <thead>
                  <tr className="border-b border-line bg-sunken/50">
                    <th className="th">{t('fleet.col.status')}</th>
                    <th className="th">{t('fleet.col.node')}</th>
                    <th className="th">{t('fleet.col.nginx')}</th>
                    <th className="th">{t('fleet.col.module')}</th>
                    <th className="th">{t('fleet.col.bundle')}</th>
                    <th className="th">{t('fleet.col.lastSeen')}</th>
                    <th className="th">{t('fleet.col.cert')}</th>
                    {canRevoke && <th className="th text-right">{t('common.actions', 'Actions')}</th>}
                  </tr>
                </thead>
                <tbody>
                  {members.length === 0 && (
                    <tr><td colSpan={canRevoke ? 8 : 7} className="td py-6 text-center text-muted">{t('fleet.groupEmpty')}</td></tr>
                  )}
                  {members.map((n) => {
                    const s = statusOf(n);
                    return (
                      <tr key={n.id} data-testid="node-row" data-node={n.id} data-status={s} className="border-b border-line last:border-0">
                        <td className="td whitespace-nowrap">
                          <span className={`mr-2 inline-block h-2 w-2 rounded-full ${dot[s]}`} />
                          <span data-testid="node-status">{t(`fleet.status.${s}`)}</span>
                        </td>
                        <td className="td">
                          <div className="font-medium">{n.hostname || n.id}</div>
                          <div className="font-mono text-xs text-faint">{n.id}</div>
                        </td>
                        <td className="td text-muted" data-testid="node-nginx">{n.proxy_version || '—'}</td>
                        <td className="td text-muted" data-testid="node-module">{n.module_version || '—'}</td>
                        <td className="td whitespace-nowrap">
                          <span className="mr-2" data-testid="node-bundle">
                            {n.bundle_version ? `v${n.bundle_version}` : '—'}
                          </span>
                          {n.bundle_version && <StateBadge state={n.bundle_state} testId="node-bundle-state" />}
                        </td>
                        <td className="td whitespace-nowrap text-muted" title={formatTime(n.last_seen_time, i18n.language, t('common.never'))}>
                          {n.last_seen_time ? relativeTime(n.last_seen_time, i18n.language) : t('common.never')}
                        </td>
                        <td className="td whitespace-nowrap text-muted">{formatTime(n.cert_expire_time, i18n.language, t('common.never'))}</td>
                        {canRevoke && (
                          <td className="td text-right whitespace-nowrap">
                            {s !== 'revoked' && (
                              <button
                                type="button"
                                className="btn py-1 px-2 h-7 text-xs text-block hover:bg-block/10"
                                data-testid="revoke-node-btn"
                                onClick={() => setRevokingNode(n)}
                              >
                                {t('fleet.revoke', 'Revoke')}
                              </button>
                            )}
                          </td>
                        )}
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </section>
        );
      })}
      {revokingNode && (
        <DestructiveConfirmModal
          title={t('fleet.revokeModal.title', {
            name: revokingNode.hostname || revokingNode.id,
            defaultValue: `Revoke Node Certificate: ${revokingNode.hostname || revokingNode.id}`,
          })}
          description={t(
            'fleet.revokeModal.desc',
            'Permanently invalidates mTLS certificates for this proxy node. It will be immediately disconnected from the fleet and blocked from receiving bundles. This cannot be undone.'
          )}
          expectedMatch={revokingNode.id ?? ''}
          requireReason={true}
          minReasonLength={10}
          confirmLabel={t('fleet.revokeModal.confirm', 'Revoke Certificate')}
          onConfirm={async () => {
            if (revokingNode.id) {
              await apiClient.revokeNode(revokingNode.id);
              void refresh();
            }
          }}
          onClose={() => setRevokingNode(null)}
        />
      )}
    </PageShell>
  );
};
