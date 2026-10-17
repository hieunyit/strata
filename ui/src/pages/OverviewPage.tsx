import React, { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Pause, Play, RefreshCw, Activity, ShieldAlert, Eye, AlertTriangle, Globe, Server, Zap, ArrowRight } from 'lucide-react';
import { AppShell } from '../components/layout/AppShell';
import { PageHeader, RangeSwitch, ErrorBanner, SectionTitle, Empty, formatCount, relativeTime, VerdictBadge } from '../components/ui';
import { StrataChart } from '../components/overview/StrataChart';
import { GeoMap } from '../components/geo/GeoMap';
import { FilterChips, FilterState } from '../components/geo/FilterChips';
import { TimelineChart } from '../components/geo/TimelineChart';
import { QuickActionModal } from '../components/geo/QuickActionModal';
import { DecisionTraceModal } from '../components/events/DecisionTraceModal';
import { apiClient, Overview, FleetNode, Rollout, Policy, TimelineResponse, Event } from '../api/client';
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
  const overview: Overview = { ...o, series: o.series ?? [], top_rules: o.top_rules ?? [], top_routes: o.top_routes ?? [], inspection: o.inspection ?? [] };
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
    <div className="flex h-2.5 w-full overflow-hidden rounded-full bg-sunken border border-line/60" aria-hidden>
      <div className="bg-rose-500 shadow-[0_0_8px_rgba(244,63,94,0.7)] transition-all" style={{ width: w(block) }} />
      <div className="bg-amber-500 shadow-[0_0_8px_rgba(245,158,11,0.7)] transition-all" style={{ width: w(shadow) }} />
      <div className="bg-purple-500 shadow-[0_0_8px_rgba(168,85,247,0.7)] transition-all" style={{ width: w(error) }} />
      <div className="bg-slate-600/50 transition-all" style={{ width: w(Math.max(0, total - block - shadow - error)) }} />
    </div>
  );
};

const Kpi: React.FC<{
  label: string;
  value: string;
  note?: string;
  tone?: 'block' | 'shadow' | 'unchecked';
  testId: string;
  icon: React.ComponentType<{ className?: string }>;
}> = ({ label, value, note, tone, testId, icon: Icon }) => {
  const toneColors = {
    block: 'text-rose-400 bg-rose-500/15 border-rose-500/30 shadow-[0_0_12px_rgba(244,63,94,0.15)]',
    shadow: 'text-amber-400 bg-amber-500/15 border-amber-500/30 shadow-[0_0_12px_rgba(245,158,11,0.15)]',
    unchecked: 'text-purple-400 bg-purple-500/15 border-purple-500/30 shadow-[0_0_12px_rgba(168,85,247,0.15)]',
  };
  const toneIconClass = tone ? toneColors[tone] : 'text-cyan-400 bg-cyan-500/10 border-cyan-500/25 shadow-[0_0_12px_rgba(6,182,212,0.15)]';
  return (
    <div
      data-testid={testId}
      className="relative overflow-hidden min-w-0 p-4 rounded-xl bg-surface border border-line shadow-sm hover:border-accent/40 transition-all flex flex-col justify-between"
    >
      <div className="flex items-center justify-between gap-2">
        <span className="text-[11px] font-bold text-muted uppercase tracking-wider truncate">{label}</span>
        <div className={`w-7 h-7 rounded-lg border flex items-center justify-center shrink-0 ${toneIconClass}`}>
          <Icon className="w-3.5 h-3.5" />
        </div>
      </div>
      <div className="mt-3">
        <div
          className={`font-mono text-[26px] leading-tight font-extrabold tabular-nums tracking-tight ${
            tone ? { block: 'text-rose-400', shadow: 'text-amber-400', unchecked: 'text-purple-400' }[tone] : 'text-ink'
          }`}
        >
          {value}
        </div>
        {note && <div className="mt-1.5 text-xs text-muted truncate">{note}</div>}
      </div>
    </div>
  );
};


export const OverviewPage: React.FC<{ route: Route }> = ({ route }) => {
  const { t, i18n } = useTranslation();
  const { maskIp } = useAuth();
  const locale = i18n.language;
  const initialCountry = route.query?.country_iso ?? null;
  const initialASN = route.query?.asn ? Number(route.query.asn) : null;
  const initialAction: 'all' | 'block' | 'monitor' =
    route.query?.action === 'block' || route.query?.action === 'monitor' ? route.query.action : 'all';

  const [range, setRange] = useState<RangeKey>(isRange(route.query?.range, overviewRanges) ? (route.query!.range as RangeKey) : '24h');
  const [policy, setPolicy] = useState(route.query?.policy_id ?? '');
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [data, setData] = useState<Data | undefined>();
  const [error, setError] = useState<string | undefined>();
  const [loading, setLoading] = useState(true);
  const [live, setLive] = useState(true);
  const [updated, setUpdated] = useState<string | undefined>();
  const [filterState, setFilterState] = useState<FilterState>({
    timeRange: (['1h', '24h', '7d', '30d'].includes(range) ? (range as any) : '24h'),
    action: initialAction,
    category: 'all',
    selectedCountry: initialCountry,
    selectedASN: initialASN,
  });
  const [timelineData, setTimelineData] = useState<TimelineResponse | null>(null);
  const [liveStreaming, setLiveStreaming] = useState<boolean>(true);

  // Drill-down attack events state
  const [drillEvents, setDrillEvents] = useState<Event[]>([]);
  const [drillTotal, setDrillTotal] = useState<number>(0);
  const [drillLoading, setDrillLoading] = useState<boolean>(false);

  // Modals state
  const [quickModalOpen, setQuickModalOpen] = useState(false);
  const [quickModalType, setQuickModalType] = useState<'geo' | 'asn'>('geo');
  const [quickModalTarget, setQuickModalTarget] = useState<string>('');
  const [quickModalAction, setQuickModalAction] = useState<'block' | 'challenge'>('block');
  const [selectedEventForTrace, setSelectedEventForTrace] = useState<Event | null>(null);

  const openQuickRule = (t: 'geo' | 'asn', target: string, act: 'block' | 'challenge' = 'block') => {
    setQuickModalType(t);
    setQuickModalTarget(target);
    setQuickModalAction(act);
    setQuickModalOpen(true);
  };

  useEffect(() => {
    const fetchTimeline = async () => {
      try {
        const res = await apiClient.getTimelineStats({
          ...windowOf(filterState.timeRange as RangeKey),
          policy_id: policy || undefined,
          country_iso: filterState.selectedCountry ?? undefined,
          asn: filterState.selectedASN ?? undefined,
          action: filterState.action !== 'all' ? filterState.action : undefined,
        });
        setTimelineData(res);
      } catch {
        // Timeline is best effort
      }
    };
    void fetchTimeline();
  }, [filterState, policy]);

  const fetchDrillEvents = useCallback(async () => {
    setDrillLoading(true);
    try {
      const res = await apiClient.searchEvents({
        ...windowOf(range),
        policy_id: policy || undefined,
        country_iso: filterState.selectedCountry || undefined,
        asn: filterState.selectedASN || undefined,
        action: filterState.action !== 'all' ? (filterState.action as any) : undefined,
        page_size: 10,
      });
      setDrillEvents(res.events || []);
      setDrillTotal(res.total_matched || 0);
    } catch {
      setDrillEvents([]);
      setDrillTotal(0);
    } finally {
      setDrillLoading(false);
    }
  }, [range, policy, filterState.selectedCountry, filterState.selectedASN, filterState.action]);

  useEffect(() => {
    void fetchDrillEvents();
  }, [fetchDrillEvents]);

  useEffect(() => {
    if (!liveStreaming) return;
    const unsub = apiClient.openGeoWatchStream((_update) => {
      setUpdated(new Date().toISOString());
      void fetchDrillEvents();
    });
    return unsub;
  }, [liveStreaming, fetchDrillEvents]);

  const refresh = useCallback(async () => {
    try {
      setData(await load(range, policy));
      setError(undefined);
      setUpdated(new Date().toISOString());
      void fetchDrillEvents();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, [range, policy, fetchDrillEvents]);

  useEffect(() => {
    setLoading(true);
    void refresh();
  }, [refresh, range, policy]);

  useEffect(() => {
    replaceQuery({
      page: 'overview',
      query: {
        range,
        ...(policy ? { policy_id: policy } : {}),
        ...(filterState.selectedCountry ? { country_iso: filterState.selectedCountry } : {}),
        ...(filterState.selectedASN ? { asn: String(filterState.selectedASN) } : {}),
        ...(filterState.action !== 'all' ? { action: filterState.action } : {}),
      },
    });
  }, [range, policy, filterState.selectedCountry, filterState.selectedASN, filterState.action]);

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
  const eventsHref = (q: Record<string, string>) =>
    href({
      page: 'events',
      query: {
        range,
        ...(policy ? { policy_id: policy } : {}),
        ...(filterState.selectedCountry ? { client_ip: filterState.selectedCountry } : {}),
        ...(filterState.action !== 'all' ? { action: filterState.action } : {}),
        ...q,
      },
    });
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

      <section className="mb-6" aria-label={t('overview.totals')}>
        <div className="grid grid-cols-2 sm:grid-cols-3 xl:grid-cols-6 gap-3.5">
          <Kpi testId="kpi-events" icon={Activity} label={t('overview.kpi.events')} value={loading && !o ? '—' : formatCount(totals?.events, locale)} note={t(`overview.kpi.window.${range}`)} />
          <Kpi
            testId="kpi-blocked"
            icon={ShieldAlert}
            tone="block"
            label={t('overview.kpi.blocked')}
            value={loading && !o ? '—' : formatCount(totals?.block, locale)}
            note={totals ? t('overview.kpi.share', { pct: pct(totals.block, totals.events) }) : undefined}
          />
          <Kpi
            testId="kpi-shadow"
            icon={Eye}
            tone="shadow"
            label={t('overview.kpi.shadow')}
            value={loading && !o ? '—' : formatCount(totals?.shadow, locale)}
            note={t('overview.kpi.shadowNote')}
          />
          <Kpi
            testId="kpi-unchecked"
            icon={AlertTriangle}
            tone={totals && totals.error > 0 ? 'unchecked' : undefined}
            label={t('overview.kpi.unchecked')}
            value={loading && !o ? '—' : formatCount(totals?.error, locale)}
            note={totals ? t('overview.kpi.uncheckedNote', { pct: pct(totals.error ?? 0, totals.events) }) : undefined}
          />
          <Kpi testId="kpi-clients" icon={Globe} label={t('overview.kpi.clients')} value={loading && !o ? '—' : formatCount(totals?.clients, locale)} note={t('overview.kpi.policies', { count: totals?.policies ?? 0 })} />
          <Kpi
            testId="kpi-nodes"
            icon={Server}
            label={t('overview.kpi.nodes')}
            value={nodes ? `${online}/${enrolled}` : '—'}
            note={nodes ? (offline.length ? t('overview.kpi.offline', { count: offline.length }) : t('overview.kpi.allOnline')) : t('overview.kpi.noFleet')}
          />
        </div>
      </section>

      <section className="mb-4">
        <FilterChips
          filters={filterState}
          onChange={(newFilters) => {
            setFilterState(newFilters);
            if (newFilters.timeRange !== range) {
              setRange(newFilters.timeRange as RangeKey);
            }
          }}
          liveStreaming={liveStreaming}
          onToggleLive={() => setLiveStreaming(!liveStreaming)}
        />
      </section>

      <section className="mb-6">
        <GeoMap
          policyId={policy}
          selectedCountry={filterState.selectedCountry}
          selectedASN={filterState.selectedASN}
          timeRangeDays={filterState.timeRange === '1h' ? 0.04 : filterState.timeRange === '7d' ? 7 : filterState.timeRange === '30d' ? 30 : 1}
          actionFilter={filterState.action}
          categoryFilter={filterState.category}
          onSelectCountry={(iso) => {
            setFilterState((prev) => ({ ...prev, selectedCountry: iso || null }));
          }}
          onSelectASN={(asn) => {
            setFilterState((prev) => ({ ...prev, selectedASN: asn || null }));
          }}
          onQuickAction={(t, tgt, act) => openQuickRule(t, tgt, act ?? 'block')}
        />
      </section>

      {timelineData && timelineData.buckets && timelineData.buckets.length > 0 && (
        <section className="mb-6">
          <TimelineChart
            buckets={timelineData.buckets}
            step={timelineData.step}
            activeFilter={
              filterState.selectedCountry
                ? `Country: ${filterState.selectedCountry}`
                : filterState.selectedASN
                ? `ASN: AS${filterState.selectedASN}`
                : undefined
            }
          />
        </section>
      )}

      {/* Drill-down Attack Events Section (W19-F-01) */}
      <section className="panel mb-6" data-testid="drilldown-events-section">
        <div className="flex flex-wrap items-center justify-between gap-3 px-5 py-4 border-b border-line bg-surface/50">
          <div className="flex items-center gap-2.5">
            <div className="w-7 h-7 rounded-lg bg-rose-500/10 border border-rose-500/25 flex items-center justify-center text-rose-400">
              <ShieldAlert className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-ink flex items-center gap-2">
                <span>Recent Filtered Attacks</span>
                {filterState.selectedCountry && (
                  <span className="font-mono text-xs px-2 py-0.5 rounded bg-rose-500/20 text-rose-400 border border-rose-500/35">
                    Quốc gia: {filterState.selectedCountry}
                  </span>
                )}
                {filterState.selectedASN && (
                  <span className="font-mono text-xs px-2 py-0.5 rounded bg-amber-500/20 text-amber-400 border border-amber-500/35">
                    ASN: AS{filterState.selectedASN}
                  </span>
                )}
              </h3>
              <p className="text-[11px] text-muted">
                {drillTotal} sự kiện phát hiện trong khung thời gian ({range})
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              data-testid="open-quick-rule-btn"
              onClick={() =>
                openQuickRule(
                  filterState.selectedCountry ? 'geo' : filterState.selectedASN ? 'asn' : 'geo',
                  filterState.selectedCountry || (filterState.selectedASN ? String(filterState.selectedASN) : ''),
                  'block'
                )
              }
              className="btn bg-rose-600/90 hover:bg-rose-600 text-white font-semibold text-xs flex items-center gap-1.5 shadow-sm"
            >
              <Zap className="w-3.5 h-3.5 text-amber-300" />
              <span>⚡ Tạo Rule Chặn Geo/ASN</span>
            </button>
            <a
              href={href({
                page: 'events',
                query: {
                  range,
                  ...(policy ? { policy_id: policy } : {}),
                  ...(filterState.selectedCountry ? { country_iso: filterState.selectedCountry } : {}),
                  ...(filterState.selectedASN ? { asn: String(filterState.selectedASN) } : {}),
                  ...(filterState.action !== 'all' ? { action: filterState.action } : {}),
                },
              })}
              className="btn btn-sm text-xs font-mono"
            >
              <span>Xem tất cả</span>
              <ArrowRight className="w-3 h-3" />
            </a>
          </div>
        </div>

        <div className="overflow-x-auto">
          {drillLoading && drillEvents.length === 0 ? (
            <div className="py-8 text-center text-xs text-muted font-mono">{t('common.loading')}</div>
          ) : drillEvents.length === 0 ? (
            <div className="py-8 text-center text-xs text-muted font-mono">
              Không có sự kiện tấn công nào khớp với bộ lọc hiện tại.
            </div>
          ) : (
            <table className="w-full text-[13px]" data-testid="drilldown-events-table">
              <thead>
                <tr className="border-b border-line text-left text-muted text-xs bg-sunken/40">
                  <th className="py-2.5 px-4">Thời gian</th>
                  <th className="py-2.5 px-4">Hành vi</th>
                  <th className="py-2.5 px-4">Nguồn (IP & Geo)</th>
                  <th className="py-2.5 px-4">Mục tiêu (Route)</th>
                  <th className="py-2.5 px-4">Rule vi phạm</th>
                  <th className="py-2.5 px-4 text-right">Thao tác</th>
                </tr>
              </thead>
              <tbody>
                {drillEvents.map((ev) => (
                  <tr
                    key={ev.block_id}
                    data-testid={`drill-event-row-${ev.block_id}`}
                    className="border-b border-line/50 last:border-0 hover:bg-sunken/60 transition-colors"
                  >
                    <td className="py-2.5 px-4 font-mono text-xs text-muted whitespace-nowrap">
                      {new Date(ev.timestamp).toLocaleTimeString(locale)}
                    </td>
                    <td className="py-2.5 px-4">
                      <VerdictBadge action={ev.action} />
                    </td>
                      <td className="py-2.5 px-4">
                        <div className="font-mono text-xs font-semibold text-accent">
                          {maskIp(ev.client_ip)}
                        </div>
                        <div className="text-[11px] text-muted flex items-center gap-1.5 mt-0.5">
                          {ev.country_iso && (
                            <span className="font-bold text-slate-300">{ev.country_iso}</span>
                          )}
                          {ev.city && <span>• {ev.city}</span>}
                          {ev.asn && <span className="font-mono text-[10px] text-amber-400/90">AS{ev.asn}</span>}
                        </div>
                      </td>
                      <td className="py-2.5 px-4">
                        <div className="font-mono text-xs text-ink truncate max-w-[220px]" title={`${ev.http_method} ${ev.http_path}`}>
                          <span className="text-accent font-semibold mr-1.5">{ev.http_method}</span>
                          <span>{ev.http_path}</span>
                        </div>
                      </td>
                      <td className="py-2.5 px-4">
                        {ev.violations && ev.violations.length > 0 ? (
                          <div className="flex flex-wrap gap-1">
                            {ev.violations.slice(0, 2).map((viol, idx) => (
                              <span
                                key={idx}
                                className="font-mono text-[11px] px-1.5 py-0.5 rounded bg-rose-500/10 text-rose-300 border border-rose-500/20"
                              >
                                #{viol.rule_id} ({viol.layer})
                              </span>
                            ))}
                            {ev.violations.length > 2 && (
                              <span className="text-[10px] text-muted font-mono self-center">
                                +{ev.violations.length - 2}
                              </span>
                            )}
                          </div>
                        ) : ev.matched_rules && ev.matched_rules.length > 0 ? (
                          <span className="font-mono text-[11px] text-muted">
                            Rules: {ev.matched_rules.slice(0, 2).join(', ')}
                          </span>
                        ) : (
                          <span className="text-muted text-xs">—</span>
                        )}
                      </td>
                      <td className="py-2.5 px-4 text-right">
                        <button
                          type="button"
                          data-testid={`trace-btn-${ev.block_id}`}
                          onClick={() => setSelectedEventForTrace(ev)}
                          className="px-2.5 py-1 rounded-lg bg-accent/10 text-accent border border-accent/25 hover:bg-accent/20 font-medium text-xs transition-colors"
                        >
                          Decision Trace
                        </button>
                      </td>
                    </tr>
                  ))}
              </tbody>
            </table>
          )}
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
                        <div className="flex items-center gap-2">
                          <a href={eventsHref({ rule_id: String(r.rule_id) })} className="font-mono font-bold text-accent px-1.5 py-0.5 rounded bg-accent/10 border border-accent/25 hover:bg-accent/20 transition-colors">
                            {r.rule_id}
                          </a>
                          <span className="text-[10px] font-mono font-bold uppercase tracking-wider px-1.5 py-0.5 rounded bg-rose-500/10 text-rose-400 border border-rose-500/20">
                            {r.rule_id >= 940000 ? 'OWASP CRS' : r.rule_id >= 700000 ? 'VIRTUAL PATCH' : 'CUSTOM'}
                          </span>
                        </div>
                        <div className="text-xs text-muted truncate max-w-[42ch] mt-1" title={meta?.name}>
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
                      <div className="font-mono text-ink font-semibold truncate max-w-[44ch]" title={`${r.host}${r.path_prefix}`}>
                        <span className="text-muted font-normal">{r.host}</span>
                        {r.path_prefix || '/'}
                      </div>
                      <div className="mt-1 flex items-center gap-2">
                        <a href={eventsHref({ policy_id: r.policy_id })} className="text-[11px] font-mono text-accent hover:underline">
                          policy: {r.policy_id || t('overview.noPolicy')}
                        </a>
                      </div>
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
      </div>

      <div className="grid gap-5 xl:grid-cols-3 mt-5">
        <section className="panel" data-testid="inspection">
          <SectionTitle aside={t('overview.inspection.note')}>{t('overview.inspection.title')}</SectionTitle>
          {o && o.inspection.length > 0 ? (
            <table className="w-full text-[13px]">
              <thead>
                <tr className="border-b border-line">
                  <th className="th">{t('overview.inspection.policy')}</th>
                  <th className="th text-right">{t('overview.inspection.requests')}</th>
                  <th className="th text-right">{t('overview.inspection.notInspected')}</th>
                </tr>
              </thead>
              <tbody>
                {o.inspection.map((p) => (
                  <tr key={p.policy_id} data-testid="inspection-row" data-policy={p.policy_id} className="border-b border-line/50 last:border-0 hover:bg-sunken/60 transition-colors">
                    <td className="td">
                      <a href={eventsHref({ policy_id: p.policy_id })} className="text-accent font-medium hover:underline">
                        {p.policy_id || t('overview.noPolicy')}
                      </a>
                    </td>
                    <td className="td text-right tabular-nums font-mono">{formatCount(p.requests, locale)}</td>
                    <td
                      className={`td text-right tabular-nums font-mono ${p.not_inspected > 0 ? 'text-unchecked font-semibold' : ''}`}
                      title={t('overview.inspection.breakdown', { partial: p.partial, body: p.body_skipped, error: p.error, degraded: p.degraded })}
                      data-testid="inspection-share"
                    >
                      {formatCount(p.not_inspected, locale)} ({pct(p.not_inspected, p.requests)}%)
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <Empty testId="inspection-empty">{loading ? t('common.loading') : t('overview.inspection.empty')}</Empty>
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
                  <tr key={c.client_ip} data-testid="top-client" className="border-b border-line/50 last:border-0 hover:bg-sunken/60 transition-colors">
                    <td className="td">
                      <a href={eventsHref({ client_ip: c.client_ip })} className="font-mono text-accent font-semibold hover:underline">
                        {maskIp(c.client_ip)}
                      </a>
                    </td>
                    <td className="td text-right tabular-nums font-mono font-bold text-rose-400">{formatCount(c.block, locale)}</td>
                    <td className="td text-right tabular-nums font-mono text-muted">{formatCount(c.events, locale)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>

        <section className="panel" data-testid="fleet-health">
          <SectionTitle aside={<a href={href({ page: 'fleet' })} className="text-accent font-medium hover:underline">{t('overview.openFleet')}</a>}>
            {t('overview.fleet')}
          </SectionTitle>
          <div className="px-5 py-4 text-[13px] space-y-3.5">
            {data?.rollout ? (
              <p data-testid="overview-rollout" className="p-2 rounded-lg bg-surface border border-line/60 font-mono text-xs">
                {t('overview.rollout', { id: data.rollout.id, version: data.rollout.bundle_version, state: t(`fleet.bundleState.${data.rollout.state}`, { defaultValue: data.rollout.state }) })}
              </p>
            ) : (
              <p className="text-muted text-xs font-mono">{t('fleet.rollout.none')}</p>
            )}
            {!nodes ? (
              <p className="text-muted">{t('overview.kpi.noFleet')}</p>
            ) : offline.length === 0 ? (
              <div className="flex items-center gap-2 p-2.5 rounded-lg bg-emerald-500/10 border border-emerald-500/25 text-emerald-400 font-medium text-xs">
                <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                <span className="font-semibold">{t('overview.allNodesOnline', { count: enrolled })}</span>
              </div>
            ) : (
              <ul className="divide-y divide-line/60" data-testid="offline-nodes">
                {offline.slice(0, 6).map((n) => (
                  <li key={n.id} className="flex items-center justify-between gap-3 py-2 text-xs">
                    <span className="flex items-center gap-2 min-w-0 font-mono">
                      <span className="w-2 h-2 rounded-full bg-rose-500" />
                      <span className="truncate text-ink font-medium">{n.hostname || n.id}</span>
                    </span>
                    <span className="text-[11px] text-muted whitespace-nowrap">
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

      <QuickActionModal
        isOpen={quickModalOpen}
        onClose={() => setQuickModalOpen(false)}
        initialType={quickModalType}
        initialTarget={quickModalTarget}
        initialAction={quickModalAction}
        policies={policies}
        currentPolicyId={policy}
        onSuccess={() => {
          void refresh();
          void fetchDrillEvents();
        }}
      />

      <DecisionTraceModal
        event={selectedEventForTrace}
        onClose={() => setSelectedEventForTrace(null)}
        onQuickAction={(t, tgt, act) => {
          openQuickRule(t, tgt, act ?? 'block');
        }}
      />
    </AppShell>
  );
};
