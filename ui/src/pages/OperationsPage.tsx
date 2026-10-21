import React,{useEffect,useRef,useState} from 'react';
import {useTranslation} from 'react-i18next';
import {apiClient,ApplicationReport,OperationalIncidentPage,ReportScheduleReply,ReportScheduleRequest} from '../api/client';
import {AppShell} from '../components/layout/AppShell';
import {ApplicationScope} from '../components/applications/ApplicationScope';
import {PageHeader} from '../components/ui';
import {useAuth} from '../context/AuthContext';
export const OperationsPage:React.FC=()=>{
 const {t,i18n}=useTranslation(),auth=useAuth();
 const [app,setApp]=useState(''),[env,setEnv]=useState(''),[global,setGlobal]=useState(false),[reload,setReload]=useState(0);
 const [incidents,setIncidents]=useState<OperationalIncidentPage>(),[schedule,setSchedule]=useState<ReportScheduleReply>(),[reports,setReports]=useState<ApplicationReport[]>([]);
 const [enabled,setEnabled]=useState(false),[hours,setHours]=useState<24|168>(24),[busy,setBusy]=useState(false),[error,setError]=useState(false),[saved,setSaved]=useState(false);
 const epoch=useRef(0),pending=useRef<ReportScheduleRequest>();
 useEffect(()=>{
  let alive=true;epoch.current++;setIncidents(undefined);setSchedule(undefined);setReports([]);setError(false);setSaved(false);pending.current=undefined;
  if(global||app&&env){
   apiClient.incidents(global?'':app,global?'':env).then(v=>alive&&setIncidents(v)).catch(()=>alive&&setError(true));
   if(!global)Promise.all([apiClient.reportSchedule(app,env),apiClient.applicationReports(app,env)]).then(([v,r])=>{if(alive){setSchedule(v);setReports(r);setEnabled(v.schedule?.enabled??false);setHours(v.schedule?.every_hours??24);}}).catch(()=>alive&&setError(true));
  }return()=>{alive=false;};
 },[app,env,global,reload]);
 const save=async()=>{
  if(!schedule?.editable||busy)return;setBusy(true);setError(false);setSaved(false);const id=epoch.current;
  pending.current??={schedule:{application_id:app,environment_id:env,enabled,every_hours:hours,etag:schedule.schedule?.etag??''},request_id:crypto.randomUUID()};
  try{const v=await apiClient.saveReportSchedule(pending.current);if(id===epoch.current){setSchedule(v);setSaved(true);pending.current=undefined;}}
  catch{if(id===epoch.current)setError(true);}finally{setBusy(false);}
 };
 const ack=async(v:OperationalIncidentPage['incidents'][number])=>{
  setBusy(true);setError(false);const id=epoch.current;
  try{await apiClient.acknowledgeIncident({id:v.id,application_id:v.application_id,environment_id:v.environment_id,etag:v.etag,request_id:crypto.randomUUID()});if(id===epoch.current)setReload(n=>n+1);}
  catch{if(id===epoch.current)setError(true);}finally{setBusy(false);}
 };
 const download=async(v:ApplicationReport)=>{
  setBusy(true);setError(false);try{const blob=await apiClient.downloadApplicationReport(v.id,app,env),url=URL.createObjectURL(blob),link=document.createElement('a');link.href=url;link.download='application-report.json';link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}catch{setError(true);}finally{setBusy(false);}
 };
 return <AppShell active="operations" wide><PageHeader title={t('operations.title')} description={t('operations.help')} actions={<button className="btn" disabled={busy} onClick={()=>setReload(n=>n+1)}>{t('common.refresh')}</button>}/>
 <fieldset className="panel p-3 mb-3" disabled={busy}>{auth.roles.includes('admin')&&!auth.scoped&&<label className="block mb-2"><input type="checkbox" checked={global} onChange={e=>setGlobal(e.target.checked)}/> {t('operations.global')}</label>}{!global&&<ApplicationScope application={app} environment={env} onChange={(a,e)=>{setApp(a);setEnv(e);}}/>}</fieldset>
 {error&&<p className="panel p-3 mb-3" role="alert">{t('operations.error')}</p>}
 {incidents&&<section className="panel p-3 mb-3"><h2>{t('operations.incidents')}</h2><p className="text-muted text-sm">{t('operations.incidentHelp')}</p>{incidents.incidents.length===0&&<p>{t('operations.noIncidents')}</p>}<table className="w-full text-sm"><thead><tr>{['cause','state','affected','observed','actions'].map(k=><th className="text-left p-2" key={k}>{t(`operations.${k}`)}</th>)}</tr></thead><tbody>{incidents.incidents.map(v=><tr key={v.id} className="border-t border-line"><td className="p-2">{t(`health.sources.${v.kind}`,{defaultValue:t('operations.signal')})}</td><td className="p-2">{t(`operations.states.${v.state}`)} · {t(`health.states.${v.signal_state}`)}</td><td className="p-2">{v.affected}</td><td className="p-2">{new Date(v.observed_at).toLocaleString(i18n.language)}</td><td className="p-2">{incidents.editable&&v.state==='open'&&<button className="btn" disabled={busy} onClick={()=>void ack(v)}>{t('operations.ack')}</button>}</td></tr>)}</tbody></table></section>}
 {schedule&&!global&&<section className="panel p-3 mb-3"><h2>{t('operations.schedule')}</h2><p className="text-sm text-muted">{t('operations.reportHelp')}</p>{schedule.scope_changed&&<p role="status">{t('operations.scopeChanged')}</p>}<fieldset className="flex gap-3 items-end mt-3" disabled={!schedule.editable||busy||!!pending.current}><label><input type="checkbox" checked={enabled} onChange={e=>{setEnabled(e.target.checked);setSaved(false);}}/> {t('operations.enabled')}</label><label>{t('operations.frequency')}<select className="field block" value={hours} onChange={e=>{setHours(Number(e.target.value) as 24|168);setSaved(false);}}><option value={24}>{t('operations.daily')}</option><option value={168}>{t('operations.weekly')}</option></select></label></fieldset>{schedule.editable&&<button className="btn mt-3" disabled={busy} onClick={()=>void save()}>{t('common.save')}</button>}{saved&&<p role="status">{t('operations.saved')}</p>}</section>}
 {!global&&!!schedule&&<section className="panel p-3"><h2>{t('operations.reports')}</h2>{reports.length===0&&<p>{t('operations.noReports')}</p>}{reports.map(v=><article key={v.id} className="border-t border-line py-3"><p>{new Date(v.period_start).toLocaleString(i18n.language)} → {new Date(v.period_end).toLocaleString(i18n.language)}</p><p>{t('operations.eventCount')}: {v.body.security_events??t('lifecycle.unknown')} · {t('operations.blockedCount')}: {v.body.blocked_security_events??t('lifecycle.unknown')}</p><p>{t('operations.measuredAt')}: {new Date(v.body.observed_at).toLocaleString(i18n.language)}</p>{v.body.truncated&&<p>{t('operations.truncated')}</p>}<button className="btn mt-2" disabled={busy} onClick={()=>void download(v)}>{t('operations.download')}</button></article>)}</section>}
 </AppShell>;
};
