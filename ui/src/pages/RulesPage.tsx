import React, { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { apiClient, RuleCatalogDetail, RuleCatalogDiff, RuleCatalogPage, RuleCatalogSnapshot } from '../api/client';
import { AppShell } from '../components/layout/AppShell';
import { PageHeader } from '../components/ui';
import { ApplicationScope } from '../components/applications/ApplicationScope';

export const RulesPage: React.FC = () => {
  const { t } = useTranslation();
  const [page, setPage] = useState<RuleCatalogPage>(), [history, setHistory] = useState<RuleCatalogSnapshot[]>([]);
  const [source, setSource] = useState(''), [cve, setCve] = useState(''), [attack, setAttack] = useState('');
  const [query, setQuery] = useState({ source: '', cve: '', attack_type: '', after: '' }), [refresh, setRefresh] = useState(0);
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
    <form className="panel p-3 mb-3 flex gap-3 flex-wrap items-end" onSubmit={(e) => { e.preventDefault(); setQuery({ source, cve, attack_type: attack, after: '' }); setDiff(undefined); }}>
      <label>{t('lifecycle.source')}<input className="field block" value={source} maxLength={64} onChange={(e) => setSource(e.target.value)}/></label>
      <label>{t('lifecycle.cve')}<input className="field block" value={cve} maxLength={32} onChange={(e) => setCve(e.target.value)}/></label>
      <label>{t('lifecycle.attack')}<input className="field block" value={attack} maxLength={64} onChange={(e) => setAttack(e.target.value)}/></label>
      <button className="btn" disabled={loading}>{t('events.filter.apply')}</button>
    </form>
    {error && <p role="alert" className="panel p-3 mb-3">{t('lifecycle.unavailable')}</p>}
    {page?.stale && <p role="status" className="panel p-3 mb-3">{t('lifecycle.stale')}</p>}
    {page && <section className="panel overflow-auto mb-3">
      <p className="p-3 text-sm text-muted">{t('lifecycle.catalogCount', { count: page.total })} · {page.at}</p>
      <table className="w-full text-sm"><thead><tr>{['rule','source','version','attack','owner','review'].map((key) => <th className="p-2 text-left" key={key}>{t(`lifecycle.${key}`)}</th>)}</tr></thead><tbody>
        {page.rules.map((r) => <tr key={r.id} className="border-t border-line"><td className="p-2"><button className="text-accent" disabled={!app || !env} onClick={() => void open(r.id)}>{r.id} · {r.name}</button><p>{r.cves?.join(', ')}</p></td><td className="p-2">{r.source} · {t(`lifecycle.packs.${r.pack}`)}</td><td className="p-2">{r.version || t('lifecycle.unknown')}</td><td className="p-2">{r.attack_type || '—'}</td><td className="p-2">{r.owner || t('lifecycle.unknown')}</td><td className="p-2">{r.review_by || t('lifecycle.unknown')}</td></tr>)}
      </tbody></table>
      {page.next_cursor > 0 && <button className="btn m-3" disabled={loading} onClick={() => setQuery({ ...query, after: String(page.next_cursor) })}>{t('common.next')}</button>}
      {query.after && <button className="btn m-3" onClick={() => setQuery({ ...query, after: '' })}>{t('lifecycle.firstPage')}</button>}
    </section>}
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
