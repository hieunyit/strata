import React, {useState,useEffect,useRef} from 'react';
import {useTranslation} from 'react-i18next';
import {apiClient, ApiError, Application, ApplicationBinding, Overview, Policy} from '../api/client';
import {useAuth} from '../context/AuthContext';
import {usePolling} from '../usePolling';
import {PageShell} from './PageShell';
import {PageHeader, ErrorBanner, formatTime} from '../components/ui';

const blank:Application={id:'',name:'',owner:'',etag:'',created_at:'',updated_at:'',environments:[],routes:[]};
export const ApplicationsPage:React.FC=()=>{
 const {t,i18n}=useTranslation(),{roles,scoped}=useAuth();
 const canWrite=!scoped && (roles.includes('admin')||roles.includes('operator'));
 const canBind=!scoped && roles.includes('admin');
 const [cursor,setCursor]=useState('');
 const apps=usePolling(()=>apiClient.listApplications(cursor),30000);
 useEffect(()=>{void apps.refresh();},[cursor,apps.refresh]);
 const inspectID=useRef(0);
 const [selected,setSelected]=useState<Application>(),[overview,setOverview]=useState<Overview>(),[error,setError]=useState<string>();
 const [edit,setEdit]=useState<Application>(),[environment,setEnvironment]=useState(''),[busy,setBusy]=useState(false);

 const bindings=usePolling(()=>canBind?apiClient.listApplicationBindings():Promise.resolve({bindings:[]}),30000);
 const [subject,setSubject]=useState(''),[role,setRole]=useState<ApplicationBinding['role']>('viewer');
 const [requestId,setRequestId]=useState('');
 const [policies,setPolicies]=useState<Policy[]>([]);
 const change=(a:Application)=>{setEdit(a);setRequestId(crypto.randomUUID());};
 const inspect=async(a:Application,env='')=>{
   const key=++inspectID.current;setSelected(a);setEnvironment(env);setOverview(undefined);setPolicies([]);setError(undefined);
   void apiClient.listPolicies().then(list=>{if(inspectID.current===key)setPolicies(list.filter(p=>a.routes.some(r=>r.policy_id===p.id)));}).catch(()=>{});
   try {const to=new Date(),from=new Date(to.getTime()-86400000);const result=await apiClient.applicationOverview(a.id,from.toISOString(),to.toISOString(),env);if(inspectID.current===key)setOverview(result);}catch{if(inspectID.current===key)setError(t('applications.unavailable'));}
 };
 const editing=(a:Application)=>{setEdit({...a});setRequestId(crypto.randomUUID());setError(undefined);};
 const save=async()=>{
   if(!edit||busy)return;setBusy(true);setError(undefined);
   try {const application=edit;const out=await apiClient.saveApplication(application,!edit.etag,requestId);setEdit(undefined);await apps.refresh();await inspect(out.application);}catch{setError(t('applications.saveFailed'));}finally{setBusy(false);}
 };
 const bindingError=(e:unknown)=>setError(t(e instanceof ApiError&&e.reason==='ADMIN_AUTHORITY_REQUIRED'?'applications.preserveAdmin':'applications.saveFailed'));
 const bind=async()=>{if(!selected||busy)return;setBusy(true);setError(undefined);try{await apiClient.createApplicationBinding({id:0,subject,role,application_id:selected.id,environment_id:environment||null,request_id:crypto.randomUUID()});await bindings.refresh();setSubject('');}catch(e){bindingError(e);}finally{setBusy(false);}};
 return <PageShell active="applications">
 <PageHeader title={t('applications.title')} description={t('applications.subtitle')} actions={canWrite&&<button className="btn" onClick={()=>editing(blank)}>{t('applications.create')}</button>}/>
 <ErrorBanner message={error||apps.error||bindings.error}/>
 {apps.loading&&<p role="status">{t('common.loading')}</p>}
 <div className="grid gap-4 lg:grid-cols-3">
 <section className="panel p-4 space-y-2">
 {(apps.data?.applications??[]).map(a=><button className="btn w-full text-left" key={a.id} onClick={()=>void inspect(a)}>{a.name} · {a.owner}</button>)}
 {apps.data?.applications.length===0&&<p>{t('applications.empty')}</p>}
 {cursor&&<button className="btn" onClick={()=>setCursor('')}>{t('applications.first')}</button>}
 {apps.data?.next_cursor&&<button className="btn" onClick={()=>setCursor(apps.data!.next_cursor)}>{t('applications.moreButton')}</button>}
 </section>
 <section className="panel p-4 space-y-4 lg:col-span-2">
 {selected&&<>
 <div className="flex gap-3 items-center"><h2>{selected.name}</h2>{canWrite&&<button className="btn" onClick={()=>editing(selected)}>{t('applications.edit')}</button>}</div>
 <p>{t('applications.owner')}: {selected.owner}</p>
 <label>{t('applications.environment')} <select className="field" value={environment} onChange={e=>void inspect(selected,e.target.value)}><option value="">{t('applications.all')}</option>{selected.environments.map(e=><option key={e.id} value={e.id}>{e.name}</option>)}</select></label>
 <p className="text-muted">{t('applications.protectionUnknown')}</p>
 {overview&&<div data-testid="application-stats">{['events','block','shadow','error'].map(k=><p key={k}>{t(`applications.${k}`)}: {overview.totals[k as keyof Overview['totals']]}</p>)}</div>}
 <table className="w-full text-sm"><thead><tr>{['host','path','policy','schema'].map(k=><th key={k}>{t(`applications.${k}`)}</th>)}</tr></thead><tbody>{selected.routes.filter(r=>!environment||r.environment_id===environment).map(r=><tr key={r.id}><td>{r.host}</td><td>{r.path_prefix}</td><td>{r.policy_id}</td><td>{r.schema_id||'—'}</td></tr>)}</tbody></table>
 <h3>{t('applications.policyChanges')}</h3>
 {policies.map(p=><p key={p.id}>{p.name} · {p.spec?.mode||t('applications.unknown')} · {formatTime(p.update_time,i18n.language,t('common.never'))}</p>)}
 <p>{t('applications.updated')}: {formatTime(selected.updated_at,i18n.language,t('common.never'))}</p>
 {canBind&&<section className="border-t pt-4 space-y-3"><h3>{t('applications.permissions')}</h3>
 <input className="field" aria-label={t('applications.subject')} value={subject} onChange={e=>setSubject(e.target.value)} placeholder="local:example-user"/>
 <select className="field" aria-label={t('applications.role')} value={role} onChange={e=>setRole(e.target.value as ApplicationBinding['role'])}>{['viewer','operator','approver','admin'].map(r=><option key={r}>{r}</option>)}</select>
 <button className="btn" disabled={busy||!subject} onClick={()=>void bind()}>{t('applications.bind')}</button>
 {(bindings.data?.bindings??[]).filter(b=>b.application_id===selected.id).map(b=><p key={b.id}>{b.subject} · {b.role} · {b.environment_id||t('applications.all')} <button className="btn" disabled={busy} onClick={()=>{setBusy(true);void apiClient.deleteApplicationBinding(b.id).then(bindings.refresh).catch(bindingError).finally(()=>setBusy(false));}}>{t('applications.revoke')}</button></p>)}
 </section>}
 </>}
 </section></div>
 {edit&&<section className="panel p-4 mt-4 space-y-3" data-testid="application-editor">
 {(['id','name','owner'] as const).map(k=><label className="block" key={k}>{t(`applications.${k}`)}<input className="field w-full" value={edit[k]} disabled={busy||(k==='id'&&!!edit.etag)} onChange={e=>{change({...edit,[k]:e.target.value});setRequestId(crypto.randomUUID());}}/></label>)}
 <p>{t('applications.routeHelp')}</p>
 <h3>{t('applications.environments')}</h3>
 {edit.environments.map((env,index)=><div className="flex flex-wrap gap-2" key={index}>{(['id','name','group_id'] as const).map(field=><label key={field}>{t(`applications.${field}`)}<input className="field" value={env[field]} onChange={e=>{change({...edit,environments:edit.environments.map((v,n)=>n===index?{...v,[field]:e.target.value}:v)});setRequestId(crypto.randomUUID());}}/></label>)}<button className="btn" onClick={()=>change({...edit,environments:edit.environments.filter((_,n)=>n!==index)})}>{t('applications.remove')}</button></div>)}
 <button className="btn" disabled={edit.environments.length>=32} onClick={()=>change({...edit,environments:[...edit.environments,{id:'',name:'',group_id:''}]})}>{t('applications.addEnvironment')}</button>
 <h3>{t('applications.routes')}</h3>
 {edit.routes.map((route,index)=><div className="flex flex-wrap gap-2" key={index}>{(['id','environment_id','host','path_prefix','policy_id','schema_id'] as const).map(field=><label key={field}>{t(`applications.${field}`)}<input className="field" value={route[field]} onChange={e=>{change({...edit,routes:edit.routes.map((v,n)=>n===index?{...v,[field]:e.target.value}:v)});setRequestId(crypto.randomUUID());}}/></label>)}<button className="btn" onClick={()=>change({...edit,routes:edit.routes.filter((_,n)=>n!==index)})}>{t('applications.remove')}</button></div>)}
 <button className="btn" disabled={edit.routes.length>=128} onClick={()=>change({...edit,routes:[...edit.routes,{id:'',environment_id:'',host:'',path_prefix:'/',policy_id:'',schema_id:''}]})}>{t('applications.addRoute')}</button>
 <button className="btn" disabled={busy} onClick={()=>void save()}>{t('common.save')}</button> <button className="btn" disabled={busy} onClick={()=>setEdit(undefined)}>{t('common.cancel')}</button>
 </section>}
 </PageShell>;
};
