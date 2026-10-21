import React,{useCallback,useEffect,useState} from 'react';
import {useTranslation} from 'react-i18next';
import {apiClient,MFAEnrollment,MFAStatus,OwnSession} from '../api/client';
import {useAuth} from '../context/AuthContext';
import {PageShell} from './PageShell';
import {PageHeader} from '../components/ui';

export const SecurityPage:React.FC=()=>{
 const {t}=useTranslation();const {isLocal,logout}=useAuth();
 const [state,setState]=useState<MFAStatus>();const [sessions,setSessions]=useState<OwnSession[]>([]);
 const [enrollment,setEnrollment]=useState<MFAEnrollment>();const [codes,setCodes]=useState<string[]>([]);
 const [password,setPassword]=useState('');const [code,setCode]=useState('');const [recovery,setRecovery]=useState(false);
 const [error,setError]=useState('');const [busy,setBusy]=useState(false);
 const load=useCallback(async()=>{const [s,list]=await Promise.all([apiClient.localMfa(),apiClient.ownSessions()]);setState(s);setSessions(list.sessions);},[]);
 useEffect(()=>{if(isLocal)void load().catch(()=>setError(t('security.failed')));},[isLocal,load,t]);
 const act=async(action:'begin'|'confirm'|'disable'|'rotate')=>{
  setBusy(true);setError('');
  try{
   const command={password,code,recovery,etag:enrollment?.etag??state?.etag,request_id:crypto.randomUUID()};
   if(action==='begin'){setCodes([]);setEnrollment(await apiClient.beginMfa(command));}
   else{const result=await (action==='confirm'?apiClient.confirmMfa(command):action==='disable'?apiClient.disableMfa(command):apiClient.rotateMfaRecovery(command));setCodes(result.recovery_codes??[]);setEnrollment(undefined);}
   setPassword('');setCode('');await load();
  }catch{setError(t('security.failed'));setCode('');}finally{setBusy(false);}
 };
 const revoke=async(session:OwnSession)=>{setBusy(true);try{await apiClient.revokeOwnSession(session.id,session.etag);if(session.current)logout();else await load();}catch{setError(t('security.failed'));}finally{setBusy(false);}};
 return <PageShell active="security"><PageHeader title={t('security.title')} description={t('security.subtitle')}/>
  {!isLocal?<p>{t('security.oidc')}</p>:<div className="max-w-3xl space-y-5">
   {error&&<p role="alert" className="text-block">{error}</p>}
   <section className="panel p-5 space-y-3"><h2 className="text-lg font-semibold">{t('security.mfa')}</h2>
    {!state?<p>{t('security.loading')}</p>:<>
     <p>{t(state.enabled?'security.enabled':'security.disabled')}{state.enabled&&` · ${t('security.remaining',{count:state.recovery_remaining})}`}</p>
     {!state.available&&<p>{t('security.unavailable')}</p>}
     <p className="text-sm text-muted">{t('security.revokeWarning')}</p>
     <label className="block">{t('security.password')}<input className="field block w-full" type="password" autoComplete="current-password" value={password} onChange={e=>setPassword(e.target.value)}/></label>
     {!state.enabled&&!enrollment&&<button className="btn-primary" disabled={busy||!password||!state.available} onClick={()=>void act('begin')}>{t('security.begin')}</button>}
     {enrollment&&<div data-testid="mfa-enrollment" className="space-y-2"><p>{t('security.enrollInstruction')}</p><code className="block break-all select-all">{enrollment.secret}</code><p className="font-mono text-xs break-all">{enrollment.uri}</p><p>{t('security.expires',{at:new Date(enrollment.expires_at).toLocaleString()})}</p></div>}
     {(state.enabled||enrollment)&&<><label className="block">{t(recovery?'security.recoveryCode':'security.code')}<input className="field block w-full" autoComplete="one-time-code" maxLength={64} value={code} onChange={e=>setCode(e.target.value.trim())}/></label>
      {state.enabled&&<label className="flex gap-2"><input type="checkbox" checked={recovery} onChange={e=>setRecovery(e.target.checked)}/>{t('security.useRecovery')}</label>}
      <div className="flex gap-2">{enrollment?<button className="btn-primary" disabled={busy||!code} onClick={()=>void act('confirm')}>{t('security.confirm')}</button>:<><button className="btn-secondary" disabled={busy||!password||!code} onClick={()=>void act('rotate')}>{t('security.rotate')}</button><button className="btn-secondary" disabled={busy||!password||!code} onClick={()=>void act('disable')}>{t('security.disable')}</button></>}</div>
     </>}
    </>}
    {codes.length>0&&<div data-testid="recovery-codes"><p>{t('security.saveCodes')}</p><pre className="font-mono select-all whitespace-pre-wrap">{codes.join('\n')}</pre><button className="btn-secondary" onClick={()=>setCodes([])}>{t('security.clearCodes')}</button></div>}
   </section>
   <section className="panel p-5 space-y-3"><h2 className="text-lg font-semibold">{t('security.sessions')}</h2>
    {sessions.map(s=><div key={s.id} className="flex justify-between items-center gap-4 border-b border-line py-2"><div><p>{s.current?t('security.current'):t('security.other')}</p><p className="text-sm text-muted">{new Date(s.created_at).toLocaleString()} · {t('security.expires',{at:new Date(s.expires_at).toLocaleString()})}</p></div><button className="btn-secondary" disabled={busy} onClick={()=>void revoke(s)}>{t('security.revoke')}</button></div>)}
   </section>
  </div>}
 </PageShell>;
};
