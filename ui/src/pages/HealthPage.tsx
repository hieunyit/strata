import React,{useEffect,useState} from 'react';
import {useTranslation} from 'react-i18next';
import {apiClient,HealthCheck} from '../api/client';
import {usePolling} from '../usePolling';
import {PageShell} from './PageShell';
import {PageHeader,ErrorBanner,formatTime,formatBytes} from '../components/ui';
export function healthState(c:HealthCheck,at:string,fresh:number,now:number,failed:boolean):HealthCheck['state']{
 if(failed)return 'unavailable';
 if(c.state!=='unknown'&&c.state!=='unavailable'&&(now-Date.parse(at)>fresh*1000||Date.parse(at)>now+5000||!Number.isFinite(Date.parse(at))))return 'stale';
 return c.state;
}
export const HealthPage:React.FC=()=>{
 const {t,i18n}=useTranslation(),data=usePolling(()=>apiClient.systemHealth(),5000);
 const [now,setNow]=useState(Date.now()),[page,setPage]=useState(0);
 useEffect(()=>{const timer=window.setInterval(()=>setNow(Date.now()),1000);return()=>clearInterval(timer);},[]);
 const snapshot=data.data;
 const rows=(checks:HealthCheck[])=><table className="w-full text-sm"><thead><tr>{['source','state','value','observed','action'].map(k=><th className="th" key={k}>{t(`health.${k}`)}</th>)}</tr></thead><tbody>{checks.map(c=>{
  const state=healthState(c,snapshot!.at,snapshot!.fresh_for_seconds,now,!!data.error);
  return <tr key={c.id} data-testid={`health-${c.id}`} data-state={state} className="border-t border-line">
   <td className="td">{t(`health.sources.${c.id}`,{defaultValue:c.id})}</td><td className="td">{t(`health.states.${state}`)}</td>
   <td className="td tabular-nums">{c.id==='certificate'&&c.value?t(`health.certificateValue.${c.value}`,{defaultValue:t('health.states.unknown')}):c.unit==='bytes'&&c.value!=null?formatBytes(c.value,i18n.language):c.value??'—'} {c.unit&&c.unit!=='bytes'?t(`health.units.${c.unit}`,{defaultValue:''}):''}</td>
   <td className="td">{formatTime(c.observed_at??undefined,i18n.language,t('health.missing'))}</td>
   <td className="td">{state==='healthy'?'—':t(`health.advice.${c.advice}`,{defaultValue:t('health.checkSource')})}</td>
  </tr>;
 })}</tbody></table>;
 return <PageShell active="health"><PageHeader title={t('health.title')} description={t('health.subtitle')} actions={<button className="btn" onClick={()=>void data.refresh()}>{t('common.refresh')}</button>}/>
 <ErrorBanner message={data.error?t('health.unavailable'):undefined}/>
 {!snapshot&&<p role="status">{data.loading?t('common.loading'):t('health.unavailable')}</p>}
 {snapshot&&<>
 <p className="mb-4">{t('health.snapshot')}: {formatTime(snapshot.at,i18n.language,t('health.missing'))} · {t(`health.scope.${snapshot.scope}`)}</p>
 <p className="mb-4 text-muted">{t('health.countersNote')}</p>
 {snapshot.truncated&&<p role="alert">{t('health.truncated')}</p>}
 <section className="panel overflow-x-auto mb-4">{rows(snapshot.checks)}</section>
 {snapshot.nodes.slice(page*50,page*50+50).map(node=><section className="panel overflow-x-auto mb-4" key={node.id}><h2 className="p-4 font-semibold">{node.id}</h2>{rows(node.checks)}</section>)}
 <div className="flex gap-3"><button className="btn" disabled={page===0} onClick={()=>setPage(page-1)}>{t('reviews.previous')}</button><button className="btn" disabled={(page+1)*50>=snapshot.nodes.length} onClick={()=>setPage(page+1)}>{t('reviews.next')}</button></div>
 </>}
 </PageShell>;
};
