import React, { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Pause, Play, RefreshCw } from 'lucide-react';
import { AppShell } from '../components/layout/AppShell';
import { PageHeader, RangeSwitch, ErrorBanner, SectionTitle, Empty, formatCount, relativeTime } from '../components/ui';
import { StrataChart } from '../components/overview/StrataChart';
import { apiClient, Overview, FleetNode, Rollout, Policy } from '../api/client';
import { RangeKey, overviewRanges, isRange, windowOf } from '../lib/timeRange';
import { Route, href, replaceQuery } from '../router';
import { useAuth } from '../context/AuthContext';

const REFRESH_MS = 30_000;

interface Data {
  overview: Overview;
  nodes?: FleetNode[];
  rollout?: Rollout;
}

async function load(range: RangeKey, policy: string): Promise<Data> {
  const o = await apiClient.getOverview({ ...windowOf(range), policy_id: policy || undefined });
  const overview: Overview = { ...o, series: o.series ?? [], top_rules: o.top_rules ?? [], top_routes: o.top_routes ?? [] };
  // The fleet part is best effort: the statistics still show without it.
  const [nodes, rollouts] = await Promise.all([
    apiClient.listNodes().catch(() => undefined),
    apiClient.listRollouts().catch(() => undefined),
  ]);
  const rollout = rollouts?.find((r) => ['RUNNING', 'PAUSED', 'FAILED'].includes(r.state ?? ''));
  return { overview, nodes, rollout };
}

const pct = (part: number, whole: number) => (whole > 0 ? Math.round((part / whole) * 1000) / 10 : 0);

// A horizontal bar split in the verdict colors, scaled to the list's top.
const SplitBar: React.FC<{ block: number; shadow: number; error?: number; total: number; max: number }> = ({ block, shadow, error = 0, total, max }) => {
  const w = (n: number) => `${max > 0 ? (n / max) * 100 : 0}%`;
  return (
    <div className="flex h-1.5 w-full overflow-hidden rounded-full bg-sunken" aria-hidden>
      <div className="bg-block" style={{ width: w(block) }} />
      <div className="bg-shadow" style={{ width: w(shadow) }} />
      <div className="bg-unchecked" style={{ width: w(error) }} />
      <div className="bg-other/60" style={{ width: w(Math.max(0, total - block - shadow - error)) }} />
    </div>
  );
};

const Kpi: React.FC<{ label: string; value: string; note?: string; tone?: 'block' | 'shadow' | 'unchecked'; testId: string }> = ({ label, value, note, tone, testId }) => (
  <div data-testid={testId} className="min-w-0 py-4 pr-4 xl:px-5 xl:first:pl-0 xl:border-l xl:first:border-l-0 border-line">
    <div className="text-xs text-muted">{label}</div>
    <div className={`mt-1 text-[26px] leading-none font-semibold tabular-nums ${tone ? { block: 'text-block', shadow: 'text-shadow', unchecked: 'text-unchecked' }[tone] : 'text-ink'}`}>
      {value}
    </div>
    {note && <div className="mt-1.5 text-xs text-muted truncate">{note}</div>}
  </div>
);

export const OverviewPage: React.FC<{ route: Route }> = ({ route }) => {
  const { t, i18n } = useTranslation();
  const { maskIp } = useAuth();
  const locale = i18n.language;
  const [range, setRange] = useState<RangeKey>(isRange(route.query?.range, overviewRanges) ? (route.query!.range as RangeKey) : '24h');
  const [policy, setPolicy] = useState(route.query?.policy_id ?? '');
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [data, setData] = useState<Data | undefined>();
  const [error, setError] = useState<string | undefined>();
  const [loading, setLoading] = useState(true);
  const [live, setLive] = useState(true);
  const [updated, setUpdated] = useState<string | undefined>();

  const refresh = useCallback(async () => {
    try {
      setData(await load(range, policy));
      setError(undefined);
      setUpdated(new Date().toISOString());
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, [range, policy]);

  useEffect(() => {
    setLoading(true);
    void refresh();
    replaceQuery({ page: 'overview', query: { range, policy_id: policy } });
  }, [refresh, range, policy]);

  useEffect(() => {
    if (!live) return;
    const id = setInterval(() => void refresh(), REFRESH_MS);
    return () => clearInterval(id);
  }, [live, refresh]);

  useEffect(() => {
    apiClient.listPolicies().then(setPolicies).catch(() => {});
  }, []);

  const o = data?.overview;
  const totals = o?.totals;
  const nodes = data?.nodes;
  const online = nodes?.filter((n) => n.online && !n.revoked).length ?? 0;
  const enrolled = nodes?.filter((n) => !n.revoked).length ?? 0;
  const offline = nodes?.filter((n) => !n.online && !n.revoked) ?? [];
  const eventsHref = (q: Record<string, string>) => href({ page: 'events', query: { range, ...(policy ? { policy_id: policy } : {}), ...q } });
  const ruleMax = o?.top_rules[0]?.events ?? 0;
  const routeMax = o?.top_routes[0]?.events ?? 0;

  return (
    <AppShell active="overview" wide>
      <PageHeader
        title={t('overview.title')}
        description={t('overview.subtitle')}
        actions={
          <>
            <label className="sr-only" htmlFor="overview-policy">
              {t('overview.policy')}
            </label>
            <select
              id="overview-policy"
              data-testid="overview-policy"
              value={policy}
              onChange={(e) => setPolicy(e.target.value)}
              className="field w-auto min-w-[11rem]"
            >
              <option value="">{t('overview.allPolicies')}</option>
              {policies.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name || p.id}
                </option>
              ))}
            </select>
            <RangeSwitch value={range} options={overviewRanges} onChange={setRange} />
            <button type="button" className="btn" data-testid="overview-live" onClick={() => setLive(!live)} aria-pressed={!live}>
              {live ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
              {live ? t('common.pause') : t('common.resume')}
            </button>
            <button type="button" className="btn" onClick={() => void refresh()} aria-label={t('common.refresh')} title={t('common.refresh')}>
              <RefreshCw className="w-3.5 h-3.5" />
            </button>
          </>
        }
      />
      <ErrorBanner message={error && t('common.refreshError', { error })} />

      <section className="panel mb-5" aria-label={t('overview.totals')}>
        <div className="grid grid-cols-2 sm:grid-cols-3 xl:grid-cols-6 px-5">
          <Kpi testId="kpi-events" label={t('overview.kpi.events')} value={loading && !o ? '—' : formatCount(totals?.events, locale)} note={t(`overview.kpi.window.${range}`)} />
          <Kpi
            testId="kpi-blocked"
            tone="block"
            label={t('overview.kpi.blocked')}
            value={loading && !o ? '—' : formatCount(totals?.block, locale)}
            note={totals ? t('overview.kpi.share', { pct: pct(totals.block, totals.events) }) : undefined}
          />
          <Kpi
            testId="kpi-shadow"
            tone="shadow"
            label={t('overview.kpi.shadow')}
            value={loading && !o ? '—' : formatCount(totals?.shadow, locale)}
            note={t('overview.kpi.shadowNote')}
          />
          <Kpi
            testId="kpi-unchecked"
            tone={totals && totals.error > 0 ? 'unchecked' : undefined}
            label={t('overview.kpi.unchecked')}
            value={loading && !o ? '—' : formatCount(totals?.error, locale)}
            note={totals ? t('overview.kpi.uncheckedNote', { pct: pct(totals.error ?? 0, totals.events) }) : undefined}
          />
          <Kpi testId="kpi-clients" label={t('overview.kpi.clients')} value={loading && !o ? '—' : formatCount(totals?.clients, locale)} note={t('overview.kpi.policies', { count: totals?.policies ?? 0 })} />
          <Kpi
            testId="kpi-nodes"
            label={t('overview.kpi.nodes')}
            value={nodes ? `${online}/${enrolled}` : '—'}
            note={nodes ? (offline.length ? t('overview.kpi.offline', { count: offline.length }) : t('overview.kpi.allOnline')) : t('overview.kpi.noFleet')}
          />
        </div>
      </section>

      <section className="panel mb-5" data-testid="overview-series">
        <SectionTitle
          aside={
            <span className="flex flex-wrap items-center gap-x-4 gap-y-1">
              {(['block', 'shadow', 'unchecked', 'pass'] as const).map((k) => (
                <span key={k} className="inline-flex items-center gap-1.5">
                  <span className={`w-2.5 h-2.5 rounded-sm ${{ block: 'bg-block', shadow: 'bg-shadow', unchecked: 'bg-unchecked', pass: 'bg-other' }[k]}`} />
                  {t(`verdict.${k}`)}
                </span>
              ))}
            </span>
          }
        >
          {t(`overview.series.${o && o.step_seconds >= 86400 ? 'daily' : o && o.step_seconds >= 21600 ? 'sixHourly' : 'hourly'}`)}
        </SectionTitle>
        <div className="px-3 pb-2 pt-1">
          {o && totals && totals.events > 0 ? (
            <StrataChart series={o.series} stepSeconds={o.step_seconds} />
          ) : (
            <Empty testId="overview-empty">{loading ? t('common.loading') : t('overview.noEvents')}</Empty>
          )}
        </div>
      </section>

      <div className="grid gap-5 xl:grid-cols-2">
        <section className="panel" data-testid="top-rules">
          <SectionTitle aside={t('overview.topNote')}>{t('overview.topRules')}</SectionTitle>
          {o && o.top_rules.length > 0 ? (
            <table className="w-full text-[13px]">
              <thead>
                <tr className="border-b border-line">
                  <th className="th">{t('overview.col.rule')}</th>
                  <th className="th w-[38%]">{t('overview.col.events')}</th>
                </tr>
              </thead>
              <tbody>
                {o.top_rules.map((r) => {
                  const meta = o.rules?.[String(r.rule_id)];
                  return (
                    <tr key={r.rule_id} data-testid="top-rule" className="border-b border-line last:border-0 hover:bg-sunken/60">
                      <td className="td min-w-0">
                        <a href={eventsHref({ rule_id: String(r.rule_id) })} className="font-mono text-accent hover:underline">
                          {r.rule_id}
                        </a>
                        <div className="text-xs text-muted truncate max-w-[42ch]" title={meta?.name}>
                          {meta?.name ?? t('overview.unknownRule')}
                        </div>
                      </td>
                      <td className="td">
                        <div className="flex items-center gap-3">
                          <SplitBar block={r.block} shadow={r.shadow} total={r.events} max={ruleMax} />
                          <span className="w-14 text-right tabular-nums">{formatCount(r.events, locale)}</span>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          ) : (
            <Empty>{loading ? t('common.loading') : t('overview.noEvents')}</Empty>
          )}
        </section>

        <section className="panel" data-testid="top-routes">
          <SectionTitle aside={t('overview.routeNote')}>{t('overview.topRoutes')}</SectionTitle>
          {o && o.top_routes.length > 0 ? (
            <table className="w-full text-[13px]">
              <thead>
                <tr className="border-b border-line">
                  <th className="th">{t('overview.col.route')}</th>
                  <th className="th w-[38%]">{t('overview.col.events')}</th>
                </tr>
              </thead>
              <tbody>
                {o.top_routes.map((r) => (
                  <tr key={`${r.policy_id}|${r.host}|${r.path_prefix}`} data-testid="top-route" className="border-b border-line last:border-0 hover:bg-sunken/60">
                    <td className="td min-w-0">
                      <div className="font-mono truncate max-w-[44ch]" title={`${r.host}${r.path_prefix}`}>
                        <span className="text-muted">{r.host}</span>
                        {r.path_prefix || '/'}
                      </div>
                      <a href={eventsHref({ policy_id: r.policy_id })} className="text-xs text-accent hover:underline">
                        {r.policy_id || t('overview.noPolicy')}
                      </a>
                    </td>
                    <td className="td">
                      <div className="flex items-center gap-3">
                        <SplitBar block={r.block} shadow={r.shadow} error={r.error} total={r.events} max={routeMax} />
                        <span className="w-14 text-right tabular-nums">{formatCount(r.events, locale)}</span>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <Empty>{loading ? t('common.loading') : t('overview.noEvents')}</Empty>
          )}
        </section>

        <section className="panel" data-testid="top-clients">
          <SectionTitle>{t('overview.topClients')}</SectionTitle>
          {!o?.top_clients ? (
            <Empty testId="top-clients-hidden">{o ? t('overview.clientsHidden') : t('common.loading')}</Empty>
          ) : o.top_clients.length === 0 ? (
            <Empty>{t('overview.noEvents')}</Empty>
          ) : (
            <table className="w-full text-[13px]">
              <thead>
                <tr className="border-b border-line">
                  <th className="th">{t('overview.col.client')}</th>
                  <th className="th text-right">{t('overview.col.blocked')}</th>
                  <th className="th text-right">{t('overview.col.events')}</th>
                </tr>
              </thead>
              <tbody>
                {o.top_clients.map((c) => (
                  <tr key={c.client_ip} data-testid="top-client" className="border-b border-line last:border-0 hover:bg-sunken/60">
                    <td className="td">
                      <a href={eventsHref({ client_ip: c.client_ip })} className="font-mono text-accent hover:underline">
                        {maskIp(c.client_ip)}
                      </a>
                    </td>
                    <td className="td text-right tabular-nums text-block">{formatCount(c.block, locale)}</td>
                    <td className="td text-right tabular-nums">{formatCount(c.events, locale)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>

        <section className="panel" data-testid="fleet-health">
          <SectionTitle aside={<a href={href({ page: 'fleet' })} className="text-accent hover:underline">{t('overview.openFleet')}</a>}>
            {t('overview.fleet')}
          </SectionTitle>
          <div className="px-4 py-3 text-[13px] space-y-3">
            {data?.rollout ? (
              <p data-testid="overview-rollout">
                {t('overview.rollout', { id: data.rollout.id, version: data.rollout.bundle_version, state: t(`fleet.bundleState.${data.rollout.state}`, { defaultValue: data.rollout.state }) })}
              </p>
            ) : (
              <p className="text-muted">{t('fleet.rollout.none')}</p>
            )}
            {!nodes ? (
              <p className="text-muted">{t('overview.kpi.noFleet')}</p>
            ) : offline.length === 0 ? (
              <p className="text-ok">{t('overview.allNodesOnline', { count: enrolled })}</p>
            ) : (
              <ul className="divide-y divide-line" data-testid="offline-nodes">
                {offline.slice(0, 6).map((n) => (
                  <li key={n.id} className="flex items-center justify-between gap-3 py-1.5">
                    <span className="flex items-center gap-2 min-w-0">
                      <span className="w-2 h-2 rounded-full bg-faint" />
                      <span className="truncate">{n.hostname || n.id}</span>
                    </span>
                    <span className="text-xs text-muted whitespace-nowrap">
                      {n.last_seen_time ? t('overview.lastSeen', { when: relativeTime(n.last_seen_time, locale) }) : t('common.never')}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </section>
      </div>
      {updated && (
        <p className="mt-4 text-xs text-faint" data-testid="overview-updated">
          {t('overview.updated', { when: new Date(updated).toLocaleTimeString(locale) })}
          {live ? `, ${t('overview.autoRefresh')}` : ''}
        </p>
      )}
    </AppShell>
  );
};
