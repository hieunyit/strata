import React, { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { apiClient, Application, EvidenceExport, SavedSearch, SavedSearchInput, SearchEventsRequest } from '../../api/client';
import { navigate } from '../../router';

export const InvestigationSearchPanel: React.FC<{ filter: SearchEventsRequest; savedId?: string }> = ({ filter, savedId }) => {
  const { t } = useTranslation();
  const [apps, setApps] = useState<Application[]>([]), [cursor, setCursor] = useState('');
  const [app, setApp] = useState(''), [env, setEnv] = useState(''), [title, setTitle] = useState(''), [shared, setShared] = useState(false);
  const [searches, setSearches] = useState<SavedSearch[]>([]), [saved, setSaved] = useState<SavedSearch>();
  const [history,setHistory]=useState<EvidenceExport[]>([]);
  const [job, setJob] = useState<EvidenceExport>(), [busy, setBusy] = useState(false), [error, setError] = useState(false);
  const pendingSave = useRef<{ search: SavedSearchInput; id: string; create: boolean }>(), pendingExport = useRef<{ filter: SearchEventsRequest; application_id: string; environment_id: string; request_id: string }>();
  const selected = apps.find((a) => a.id === app);
  const loadApps = async (after = '') => {
    try { const r = await apiClient.listApplications(after); setApps((old) => after ? [...old, ...r.applications] : r.applications); setCursor(r.next_cursor ?? ''); }
    catch { setError(true); }
  };
  useEffect(() => { void loadApps(); }, []);
  useEffect(() => {
    let active = true; setSaved(undefined);
    if (savedId) apiClient.savedSearch(savedId).then((value) => { if (active) { setSaved(value); setApp(value.application_id); setEnv(value.environment_id);setTitle(value.title);setShared(value.shared); } }).catch(() => active && setError(true));
    return () => { active = false; };
  }, [savedId]);
  useEffect(() => {
    let active = true; setSearches([]);
    if (app && env) apiClient.savedSearches(app, env).then((r) => active && setSearches(r.searches)).catch(() => active && setError(true));
    return () => { active = false; };
  }, [app, env]);
  useEffect(()=>{
    let active=true;setHistory([]);setJob(undefined);
    if(app&&env) apiClient.evidenceList(app,env).then((r)=>{if(active){setHistory(r.exports);setJob(r.exports[0]);}}).catch(()=>active&&setError(true));
    return ()=>{active=false;};
  },[app,env]);
  useEffect(() => {
    if (!job || !['pending', 'running'].includes(job.state)) return;
    let active = true;
    const timer = setInterval(() => { apiClient.evidence(job.id).then((v) => active && setJob(v)).catch(() => active && setError(true)); }, 3000);
    return () => { active = false; clearInterval(timer); };
  }, [job]);
  const run = async (action: () => Promise<void>) => { setBusy(true); setError(false); try { await action(); } catch { setError(true); } finally { setBusy(false); } };
  const save = (create = true) => run(async () => {
    pendingSave.current ??= { id: crypto.randomUUID(), create, search: { id: create ? '' : saved?.id, etag: create ? '' : saved?.etag, title, shared, application_id: app, environment_id: env, filter: create ? filter : saved?.filter ?? filter } };
    const value = await apiClient.saveSearch(pendingSave.current.search, pendingSave.current.id, pendingSave.current.create);
    pendingSave.current = undefined;setSaved(value); navigate({ page: 'events', query: { saved: value.id } });
  });
  const exportEvidence = () => run(async () => {
    pendingExport.current ??= { application_id: app, environment_id: env, filter: saved?.filter ?? filter, request_id: crypto.randomUUID() };
    const created=await apiClient.createEvidence(pendingExport.current);setJob(created);setHistory((old)=>[created,...old].slice(0,20)); pendingExport.current = undefined;
  });
  const download = () => run(async () => {
    if (!job) return;
    const blob = await apiClient.downloadEvidence(job.id), url = URL.createObjectURL(blob), link = document.createElement('a');
    link.href = url; link.download = `evidence-${job.id}.csv`; link.click(); URL.revokeObjectURL(url);
  });
  const frozen = busy || !!pendingSave.current || !!pendingExport.current;
  return <section className="panel p-3 mb-3" aria-label={t('investigation.searches')}>
    <div className="flex gap-2 flex-wrap items-end">
      <label>{t('investigation.application')}<select className="field block" value={app} onChange={(e) => { setApp(e.target.value); setEnv(''); }} disabled={frozen}><option value="">{t('investigation.select')}</option>{apps.map((a) => <option key={a.id} value={a.id}>{a.name}</option>)}</select></label>
      {cursor && apps.length < 1000 && <button className="btn" onClick={() => void loadApps(cursor)}>{t('investigation.more')}</button>}
      <label>{t('investigation.environment')}<select className="field block" value={env} onChange={(e) => setEnv(e.target.value)} disabled={frozen}><option value="">{t('investigation.select')}</option>{selected?.environments.map((e) => <option key={e.id} value={e.id}>{e.name}</option>)}</select></label>
      <label>{t('investigation.title')}<input className="field block" value={title} maxLength={100} onChange={(e) => setTitle(e.target.value)} disabled={frozen}/></label>
      <label><input type="checkbox" checked={shared} onChange={(e) => setShared(e.target.checked)} disabled={frozen}/>{t('investigation.share')}</label>
      <button className="btn" disabled={busy || !app || !env || !title.trim()} onClick={() => void save()}>{t('investigation.save')}</button>
      {saved?.editable&&<button className="btn" disabled={busy||!title.trim()} onClick={()=>void save(false)}>{t('investigation.update')}</button>}
      <button className="btn" disabled={busy || !app || !env || !!job && ['pending','running'].includes(job.state)} onClick={() => void exportEvidence()}>{t('investigation.export')}</button>
    </div>
    <p className="text-sm text-muted mt-2">{t('investigation.scopeHelp')}</p>
    {saved && <p className="mt-2">{saved.title} · {saved.filter.from} — {saved.filter.to} <a className="text-accent" href={`#/events?saved=${encodeURIComponent(saved.id)}`}>{t('investigation.link')}</a></p>}
    <div className="flex gap-3 mt-2">{searches.map((v) => <a key={v.id} className="text-accent" href={`#/events?saved=${encodeURIComponent(v.id)}`}>{v.title}</a>)}</div>
    {history.length>1&&<label>{t('investigation.exportHistory')}<select className="field ml-2" value={job?.id??''} onChange={(e)=>setJob(history.find((v)=>v.id===e.target.value))}>{history.map((v)=><option key={v.id} value={v.id}>{v.created_at}</option>)}</select></label>}
    {job && <div role="status" className="mt-2">{t(`investigation.jobs.${job.state}`)} · {job.row_count} {job.truncated && t('investigation.truncated')}{job.state === 'done' && <button className="btn ml-2" disabled={busy} onClick={() => void download()}>{t('investigation.download')}</button>}</div>}
    {error && <p role="alert">{t('investigation.error')}</p>}
  </section>;
};
