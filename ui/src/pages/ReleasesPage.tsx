import React,{useState,useEffect,useRef} from 'react';
import {useTranslation} from 'react-i18next';
import {apiClient,ApiError,ReleaseDetail,Operation} from '../api/client';
import {useAuth} from '../context/AuthContext';
import {usePolling} from '../usePolling';
import {ReplaySummary} from '../components/policy/ReplaySummary';
import {PageShell} from './PageShell';
import {PageHeader,ErrorBanner} from '../components/ui';

const precondition=(error:unknown)=>error instanceof ApiError&&error.code===412&&['NODES_INCOMPATIBLE','REPLAY_REQUIRED'].includes(error.reason??'')?error.message:undefined;
const Detail:React.FC<{id:string;changed:()=>void;select:(id:string)=>void}>=({id,changed,select})=>{
 const {t}=useTranslation(),{roles}=useAuth();
 const data=usePolling(()=>apiClient.getRelease(id),3000);
 const [reviewed,setReviewed]=useState(false),[ack,setAck]=useState<string>(),[error,setError]=useState(false),[busy,setBusy]=useState(false),[details,setDetails]=useState<string>();
 const [proofs,setProofs]=useState<Operation[]>([]),[proofError,setProofError]=useState(false);
 const lock=useRef(false),requestId=useRef(crypto.randomUUID());
 const release=data.data?.release;
 const evidence=JSON.stringify(release?.snapshot.replay_ids??{});
 useEffect(()=>{
  let cancelled=false;setReviewed(false);setAck(undefined);setProofError(false);setProofs([]);
  const ids=Object.values(JSON.parse(evidence) as Record<string,string>).filter(Boolean);
  void Promise.all(ids.map(value=>apiClient.getOperation(value))).then(values=>{if(!cancelled)setProofs(values.filter((v):v is Operation=>!!v));}).catch(()=>{if(!cancelled)setProofError(true);});
  return()=>{cancelled=true;};
 },[id,evidence,release?.etag]);
 if(!release)return <p role="status">{data.error?t('releases.unavailable'):t('common.loading')}</p>;
 const reviewer=roles.includes('admin')||roles.includes('approver'),writer=roles.includes('admin')||roles.includes('operator');
 const action=async(kind:'approve'|'reject'|'deploy')=>{
  if(lock.current)return;lock.current=true;setBusy(true);setError(false);setDetails(undefined);
  try{await apiClient.actRelease(id,kind,{etag:release.etag,snapshot_hash:release.snapshot_hash,replay_ids:release.snapshot.replay_ids,...(ack===data.data?.current_baseline?{ack_baseline:ack}:{})});await data.refresh();changed();}catch(e){setError(true);setDetails(precondition(e));}finally{lock.current=false;setBusy(false);}
 };
 const rollback=async()=>{if(lock.current)return;lock.current=true;setBusy(true);try{const next=await apiClient.createRelease(requestId.current,id);changed();select(next.release.id);}catch(e){setError(true);setDetails(precondition(e));}finally{lock.current=false;setBusy(false);}};
 const detail=data.data as ReleaseDetail;
 return <section className="panel p-4 space-y-4" data-testid="release-detail">
 <ErrorBanner message={data.error||(error?(details?t('releases.precondition',{details}):t('releases.writeFailed')):undefined)}/>
 <h2 className="break-all">{id} · {t(`releases.state.${release.state}`)}</h2>
 <p>{t('releases.workflow')}</p>
 <p>{t('releases.creator')}: {release.created_by} · {t('releases.reviewer')}: {release.approved_by||'—'}</p>
 <p className="break-all">{t('releases.hash')}: {release.snapshot_hash}</p>
 <p className="break-all">{t('releases.rules')}: {release.snapshot.bundle.rules_digest}</p>
 <p className="break-all">{t('releases.capabilities')}: {(release.snapshot.bundle.required_capabilities??[]).join(', ')||t('releases.baseCapabilities')}</p>
 <p className="break-all">{t('releases.inputs')}: {release.snapshot.bundle.input_digest}</p>
 <p>{t('releases.baseline')}: {release.snapshot.baseline_bundle} → {detail.current_baseline}</p>
 <ul>{Object.entries(release.snapshot.bundle.contents).map(([policy,version])=><li key={policy}>{policy} · v{version}</li>)}</ul>
 <h3>{t('releases.canary')}</h3>
 <p>{t('releases.waves')}: {release.snapshot.waves.join(' → ')} · {t('releases.soak')}: {release.snapshot.soak_seconds}s</p>
 <dl>{Object.entries(release.snapshot.canary??{}).map(([key,value])=><div key={key}><dt className="inline">{t(`releases.thresholds.${key}`)}: </dt><dd className="inline">{value}</dd></div>)}</dl>
 <p>{t('releases.comparison')}</p>
 {proofs.map(proof=><ReplaySummary key={proof.id} operation={proof}/>)}
 {proofError&&<p role="alert">{t('releases.proofUnavailable')}</p>}
 {release.state==='DRAFT'&&reviewer&&<>
 <label className="flex gap-2"><input type="checkbox" checked={reviewed} onChange={e=>setReviewed(e.target.checked)}/>{t('releases.reviewed')}</label>
 <button className="btn" disabled={busy||!reviewed||proofError||proofs.length!==Object.values(release.snapshot.replay_ids).filter(Boolean).length} onClick={()=>void action('approve')}>{t('releases.approve')}</button>
 <button className="btn" disabled={busy||!reviewed} onClick={()=>void action('reject')}>{t('releases.reject')}</button>
 </>}
 {detail.baseline_warning&&<p role="alert">{t('releases.baselineWarning')}</p>}
 {release.state==='APPROVED'&&writer&&<>
 {detail.baseline_warning&&<label className="flex gap-2"><input type="checkbox" checked={ack===detail.current_baseline} onChange={e=>setAck(e.target.checked?detail.current_baseline:undefined)}/>{t('releases.ack',{version:detail.current_baseline})}</label>}
 <button className="btn" disabled={busy||(detail.baseline_warning&&ack!==detail.current_baseline)} onClick={()=>void action('deploy')}>{t('releases.deploy')}</button>
 </>}
 {detail.rollout&&<><h3>{t('releases.rollout')} · {detail.rollout.state}</h3><p>{detail.rollout.reason}</p><ul>{detail.rollout.nodes?.map(n=><li key={n.node_id}>{n.node_id} · {n.state} {n.error}</li>)}</ul></>}
 {release.state==='DEPLOYED'&&writer&&<button className="btn" disabled={busy} onClick={()=>void rollback()}>{t('releases.rollback')}</button>}
 </section>;
};
export const ReleasesPage:React.FC=()=>{
 const {t}=useTranslation(),{roles}=useAuth();const [cursor,setCursor]=useState('');
 const releases=usePolling(()=>apiClient.listReleases(cursor),15000),[selected,setSelected]=useState(''),[error,setError]=useState(false),[busy,setBusy]=useState(false),[details,setDetails]=useState<string>();
 const requestId=useRef(crypto.randomUUID());
 useEffect(()=>{void releases.refresh();},[cursor,releases.refresh]);
 const create=async()=>{if(busy)return;setBusy(true);setError(false);try{const out=await apiClient.createRelease(requestId.current);requestId.current=crypto.randomUUID();await releases.refresh();setSelected(out.release.id);}catch(e){setError(true);setDetails(precondition(e));}finally{setBusy(false);}};
 return <PageShell active="releases"><PageHeader title={t('releases.title')} description={t('releases.subtitle')} actions={(roles.includes('operator')||roles.includes('admin'))&&<button className="btn" disabled={busy} onClick={()=>void create()}>{t('releases.prepare')}</button>}/>
 <ErrorBanner message={releases.error||(error?(details?t('releases.precondition',{details}):t('releases.writeFailed')):undefined)}/>
 <div className="flex gap-4 mb-4"><a href="#/policies">{t('releases.editPolicies')}</a><a href="#/reviews">{t('releases.reviewPolicies')}</a></div>
 <div className="grid gap-4 lg:grid-cols-3"><section className="panel p-4 space-y-2">
 {releases.data?.releases.map(r=><button className="btn w-full text-left break-all" key={r.id} onClick={()=>setSelected(r.id)}>{r.id} · {t(`releases.state.${r.state}`)}</button>)}
 {cursor&&<button className="btn" onClick={()=>setCursor('')}>{t('applications.first')}</button>}{releases.data?.next_cursor&&<button className="btn" onClick={()=>setCursor(releases.data!.next_cursor)}>{t('applications.moreButton')}</button>}
 </section><div className="lg:col-span-2">{selected&&<Detail key={selected} id={selected} select={setSelected} changed={()=>void releases.refresh()}/>}</div></div>
 </PageShell>;
};
