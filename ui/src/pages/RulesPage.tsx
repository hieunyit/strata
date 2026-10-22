import React, { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { apiClient, RuleCatalogDetail, RuleCatalogDiff, RuleCatalogPage, RuleCatalogSnapshot, RuleSet } from '../api/client';
import { AppShell } from '../components/layout/AppShell';
import { PageHeader, formatTime } from '../components/ui';
import { ApplicationScope } from '../components/applications/ApplicationScope';
import { OverrideForm } from '../components/events/RuleOverrideDraft';
import { CustomRuleSets } from '../components/rules/CustomRuleSets';
import { canWritePolicies } from '../auth/roles';
import { useAuth } from '../context/AuthContext';
import { SET_GROUPS, setTitle } from '../lib/ruleSets';

const noFilters = { source: '', cve: '', attack_type: '', q: '', set: '', after: '' };

export const RulesPage: React.FC = () => {
  const { t, i18n } = useTranslation();
  const [page, setPage] = useState<RuleCatalogPage>(), [history, setHistory] = useState<RuleCatalogSnapshot[]>([]);
  const { roles } = useAuth();
  const [cve, setCve] = useState(''), [text, setText] = useState('');
  const [query, setQuery] = useState(noFilters), [refresh, setRefresh] = useState(0);
  // RS-4b: the built-in rule sets, to filter by and to name a rule's sets
  const [sets, setSets] = useState<RuleSet[]>([]), [override, setOverride] = useState<number>(), [setsRead, setSetsRead] = useState(0);
  useEffect(() => { apiClient.listRuleSets().then((r) => setSets(r.sets), () => setSets([])); }, [setsRead]);
  const filter = (patch: Partial<typeof noFilters>) => { setQuery({ ...query, ...patch, after: '' }); setDiff(undefined); };
  const titleOf = (name: string) => { const s = sets.find((x) => x.name === name); return s ? setTitle(s, i18n.language) : name; };
  const [app, setApp] = useState(''), [env, setEnv] = useState(''), [detail, setDetail] = useState<RuleCatalogDetail>();
  const [baseline, setBaseline] = useState(''), [diff, setDiff] = useState<RuleCatalogDiff>();
  const [loading, setLoading] = useState(false), [error, setError] = useState(false);
  const epoch = useRef(0);
  useEffect(() => {
    let alive = true; setLoading(true); setError(false);
    Promise.all([apiClient.ruleCatalog(query), apiClient.catalogHistory()]).then(([value, snapshots]) => {
      if (alive) { setPage(value); setHistory(snapshots); }
    }).catch(() => alive && setError(true)).finally(() => alive && setLoading(false));
    return () => { alive = false; };
  }, [query, refresh]);
  useEffect(() => { epoch.current++; setDetail(undefined); }, [app, env]);
  const open = async (id: number) => {
    const current = ++epoch.current; setError(false);setDetail(undefined);
    try { const value = await apiClient.ruleCatalogDetail(id, app, env); if (current === epoch.current) setDetail(value); }
    catch { if (current === epoch.current) setError(true); }
  };
  const compare = async (after = '') => {
    if (!page || !baseline) return;
    setLoading(true); setError(false);
    try { setDiff(await apiClient.catalogDiff(baseline, page.digest, after)); } catch { setError(true); } finally { setLoading(false); }
  };
  return <AppShell active="rules" wide>
    <PageHeader title={t('lifecycle.rulesTitle')} description={t('lifecycle.catalogHelp')} actions={<button className="btn" onClick={() => setRefresh((v) => v + 1)}>{t('common.refresh')}</button>}/>
    <form className="panel p-3 mb-3 grid gap-3 sm:grid-cols-2 lg:grid-cols-6 items-end" onSubmit={(e) => { e.preventDefault(); filter({ q: text.trim(), cve: cve.trim() }); }} data-testid="rules-filters">
      <label className="lg:col-span-2">{t('lifecycle.search')}<input className="field block w-full" value={text} maxLength={64} onChange={(e) => setText(e.target.value)} data-testid="rules-q"/></label>
      <label>{t('lifecycle.set')}<select className="field block w-full" value={query.set} onChange={(e) => filter({ set: e.target.value })} data-testid="rules-set">
        <option value="">{t('lifecycle.any')}</option>
        {SET_GROUPS.map((g) => <optgroup key={g} label={t(`editor.ruleSets.group.${g}`)}>{sets.filter((x) => x.group === g).map((x) => <option key={x.name} value={x.name}>{setTitle(x, i18n.language)}</option>)}</optgroup>)}
      </select></label>
      <label>{t('lifecycle.source')}<select className="field block w-full" value={query.source} onChange={(e) => filter({ source: e.target.value })} data-testid="rules-source">
        <option value="">{t('lifecycle.any')}</option>
        {(page?.facets?.sources ?? []).map((v) => <option key={v} value={v}>{v}</option>)}
      </select></label>
      <label>{t('lifecycle.attack')}<select className="field block w-full" value={query.attack_type} onChange={(e) => filter({ attack_type: e.target.value })} data-testid="rules-attack">
        <option value="">{t('lifecycle.any')}</option>
        {(page?.facets?.attack_types ?? []).map((v) => <option key={v} value={v}>{v}</option>)}
      </select></label>
      <label>{t('lifecycle.cve')}<input className="field block w-full" value={cve} maxLength={32} placeholder="CVE-2026-12345" onChange={(e) => setCve(e.target.value)} data-testid="rules-cve"/></label>
      <div className="flex gap-2 sm:col-span-2 lg:col-span-6">
        <button className="btn" disabled={loading} data-testid="rules-apply">{t('events.filter.apply')}</button>
        <button type="button" className="btn" onClick={() => { setText(''); setCve(''); filter(noFilters); }}>{t('lifecycle.clear')}</button>
      </div>
    </form>
    {error && <p role="alert" className="panel p-3 mb-3">{t('lifecycle.unavailable')}</p>}
    {page?.stale && <p role="status" className="panel p-3 mb-3">{t('lifecycle.stale')}</p>}
    {page && <section className="panel relative overflow-auto mb-3">
      <p className="p-3 text-sm text-muted" data-testid="rules-matched">{t('lifecycle.matched', { matched: page.matched ?? page.total, total: page.total })} · {formatTime(page.at, i18n.language, '—')}</p>
      {override !== undefined && <div className="px-3"><OverrideForm key={override} ruleIds={[override]} names={{ [override]: page.rules.find((r) => r.id === override)?.name ?? '' }} onClose={() => setOverride(undefined)} /></div>}
      <table className="w-full text-sm"><thead><tr>{['rule','sets','source','version','attack','owner','review'].map((key) => <th className="p-2 text-left" key={key}>{t(`lifecycle.${key}`)}</th>)}{canWritePolicies(roles) && <th className="p-2"><span className="sr-only">{t('ruleOverride.open')}</span></th>}</tr></thead><tbody>
        {page.rules.map((r) => <tr key={r.id} className="border-t border-line" data-testid="rules-row"><td className="p-2"><button className="text-accent text-left" disabled={!app || !env} onClick={() => void open(r.id)}>{r.id} · {r.name}</button><p>{r.cves?.join(', ')}</p></td>
          <td className="p-2"><span className="flex flex-wrap gap-1">{(r.sets ?? []).map((n) => <button type="button" key={n} className="rounded-full border border-line px-1.5 text-[11px] text-muted hover:text-ink" onClick={() => filter({ set: n })}>{titleOf(n)}</button>)}</span></td>
          <td className="p-2">{r.source} · {t(`lifecycle.packs.${r.pack}`)}</td><td className="p-2">{r.version || t('lifecycle.unknown')}</td><td className="p-2">{r.attack_type || '—'}</td><td className="p-2" title={r.owner ? undefined : t('lifecycle.unknown')}>{r.owner || '—'}</td><td className="p-2" title={r.review_by ? undefined : t('lifecycle.unknown')}>{r.review_by || '—'}</td>
          {canWritePolicies(roles) && <td className="p-2"><button type="button" className="btn whitespace-nowrap" onClick={() => setOverride(r.id)} data-testid={`rules-override-${r.id}`}>{t('ruleOverride.openShort')}</button></td>}</tr>)}
      </tbody></table>
      {page.next_cursor > 0 && <button className="btn m-3" disabled={loading} onClick={() => setQuery({ ...query, after: String(page.next_cursor) })}>{t('common.next')}</button>}
      {query.after && <button className="btn m-3" onClick={() => setQuery({ ...query, after: '' })}>{t('lifecycle.firstPage')}</button>}
    </section>}
    <CustomRuleSets sets={sets} facets={page?.facets} canWrite={canWritePolicies(roles)} onChanged={() => setSetsRead((n) => n + 1)} />
    <section className="panel p-3 mb-3"><h2 className="font-medium mb-2">{t('lifecycle.applicationUsage')}</h2><ApplicationScope application={app} environment={env} onChange={(a,e) => { setApp(a); setEnv(e); }}/><p className="text-sm text-muted mt-2">{t('lifecycle.usageHelp')}</p>
      {detail && <div className="mt-3"><h3>{detail.rule.id} · {detail.rule.name}</h3><ul>{detail.usage.map((v) => <li key={v.policy_id}>{v.policy_name} · v{v.policy_version} · {t(`lifecycle.policyStates.${v.state}`)} · {t(`lifecycle.modes.${v.policy_mode}`)} · {t('lifecycle.activePolicyNodes', { count: v.active_policy_nodes })}{v.disabled && ` · ${t('lifecycle.disabled')}`}</li>)}</ul>
        <p className="mt-2">{t('lifecycle.cost')}: {detail.health_status === 'available' && detail.health?.cost_mean_ns != null ? `${detail.health.cost_mean_ns.toFixed(1)} ns` : t('lifecycle.unknown')}</p>
        <p className="text-sm text-muted">{t('lifecycle.costHelp')} {detail.health?.cost_samples && `${t('lifecycle.samples')}: ${detail.health.cost_samples}`}</p>
      </div>}
    </section>
    <section className="panel p-3"><h2 className="font-medium mb-2">{t('lifecycle.packDiff')}</h2><div className="flex gap-3 items-end"><label>{t('lifecycle.baseline')}<select className="field block" value={baseline} onChange={(e) => { setBaseline(e.target.value); setDiff(undefined); }}><option value="">{t('investigation.select')}</option>{history.map((v) => <option key={v.digest} value={v.digest}>{v.created_at} · {v.digest.slice(0,12)}</option>)}</select></label><button className="btn" disabled={!baseline || !page || loading} onClick={() => void compare()}>{t('lifecycle.compare')}</button></div>
      {diff && <div className="mt-3"><p>{t('lifecycle.diffCount', { added: diff.added, removed: diff.removed, modified: diff.modified })}</p><ul>{diff.changes.map((v) => <li key={v.id}>{v.id} · {t(`lifecycle.changes.${v.kind}`)} · {v.before?.version || '—'} → {v.after?.version || '—'}</li>)}</ul>{diff.next_cursor > 0 && <button className="btn mt-2" disabled={loading} onClick={() => void compare(String(diff.next_cursor))}>{t('common.next')}</button>}</div>}
    </section>
  </AppShell>;
};
