import React, { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { apiClient, EventRuleDraft, ExceptionInventoryPage, ExceptionLifecycleRequest } from '../api/client';
import { AppShell } from '../components/layout/AppShell';
import { ApplicationScope } from '../components/applications/ApplicationScope';
import { PageHeader } from '../components/ui';
import { href } from '../router';

export const ExceptionsPage: React.FC = () => {
  const { t, i18n } = useTranslation();
  const [app, setApp] = useState(''), [env, setEnv] = useState(''), [after, setAfter] = useState(''), [reload, setReload] = useState(0);
  const [page, setPage] = useState<ExceptionInventoryPage>(), [receipt, setReceipt] = useState<EventRuleDraft>();
  const [error, setError] = useState(false), [busy, setBusy] = useState(false);
  const pending = useRef<{ action: 'revoke'|'cleanupExpired'; request: ExceptionLifecycleRequest }>();
  useEffect(() => {
    let alive = true; setPage(undefined); setError(false); setReceipt(undefined); pending.current = undefined;
    if (app && env) apiClient.exceptions(app, env, after).then((v) => alive && setPage(v)).catch(() => alive && setError(true));
    return () => { alive = false; };
  }, [app, env, after, reload]);
  const act = async (action: 'revoke'|'cleanupExpired', policy: string, etag: string, exception: string) => {
    if (busy) return;setBusy(true);setError(false);
    pending.current ??= { action, request: { application_id: app, environment_id: env, policy_id: policy, exception_id: exception, etag, request_id: crypto.randomUUID() } };
    try { setReceipt(await apiClient.exceptionLifecycle(pending.current.action, pending.current.request)); pending.current = undefined; }
    catch { setError(true); } finally { setBusy(false); }
  };
  return <AppShell active="exceptions" wide>
    <PageHeader title={t('lifecycle.exceptionsTitle')} description={t('lifecycle.exceptionsHelp')} actions={<button className="btn" disabled={busy} onClick={() => setReload((v) => v + 1)}>{t('common.refresh')}</button>}/>
    <section className="panel p-3 mb-3"><fieldset disabled={busy}><ApplicationScope application={app} environment={env} onChange={(a,e) => { setApp(a);setEnv(e);setAfter(''); }}/></fieldset></section>
    {error && <p role="alert" className="panel p-3 mb-3">{t('lifecycle.actionError')}</p>}
    {receipt && <div role="status" className="panel p-3 mb-3">{t('investigation.draftCreated', { version: receipt.policy_version })} <a className="text-accent" href={href({ page:'policies' })}>{t('investigation.review')}</a></div>}
    {page && <section className="panel overflow-auto mb-3"><table className="w-full text-sm"><thead><tr>{['rule','route','field','owner','expiry','approval','actions'].map((key) => <th className="p-2 text-left" key={key}>{t(`lifecycle.${key}`)}</th>)}</tr></thead><tbody>
      {page.exceptions.map((v) => <tr key={`${v.policy_id}:${v.policy_version}:${v.exception.id}`} className="border-t border-line"><td className="p-2">{v.exception.rule_id}<p>{v.policy_name} · v{v.policy_version} · {t(`lifecycle.policyStates.${v.state}`)}</p><p className="text-muted">{t('lifecycle.activePolicyNodes', { count:v.active_nodes })}</p></td><td className="p-2 break-all">{v.exception.method} {v.exception.host}{v.exception.path}</td><td className="p-2">{v.exception.field}<p className="text-muted">{v.exception.reason || t('lifecycle.restricted')}</p></td><td className="p-2">{v.origin.owner || t('lifecycle.unknown')}</td><td className="p-2">{new Date(v.exception.expires_unix_ms).toLocaleString(i18n.language)}{v.warnings.map((key) => <p key={key} className="text-block">{t(`lifecycle.warnings.${key}`)}</p>)}<p className="text-muted">{t('lifecycle.unusedUnknown')}</p></td><td className="p-2">{v.decided_by || '—'}<p className="font-mono break-all">{v.approved_replay_id || t('lifecycle.noProof')}</p></td><td className="p-2">{v.editable && <div className="flex gap-2 flex-wrap">{(['revoke', ...(v.warnings.includes('expired') ? ['cleanupExpired'] : [])] as ('revoke'|'cleanupExpired')[]).map((action) => <button key={action} className="btn" disabled={busy || !!receipt || !!pending.current && (pending.current.action !== action || pending.current.request.exception_id !== v.exception.id)} onClick={() => void act(action,v.policy_id,v.etag,v.exception.id)}>{t(`lifecycle.${action}`)}</button>)}</div>}</td></tr>)}
    </tbody></table>{page.exceptions.length === 0 && <p className="p-3">{t('lifecycle.noExceptions')}</p>}
      {page.next_cursor && <button className="btn m-3" disabled={busy} onClick={() => setAfter(page.next_cursor)}>{t('common.next')}</button>}{after && <button className="btn m-3" disabled={busy} onClick={() => setAfter('')}>{t('lifecycle.firstPage')}</button>}
    </section>}
    {!!page?.maintenance.length && <section className="panel p-3"><h2 className="font-medium">{t('lifecycle.maintenance')}</h2><p className="text-sm text-muted">{t('lifecycle.maintenanceHelp')}</p><ul>{page.maintenance.map((v) => <li key={`${v.policy_id}:${v.source_version}`}>{v.policy_id} · v{v.source_version} · {t(`lifecycle.maintenanceStates.${v.state}`)}{v.draft_version > 0 && ` → v${v.draft_version}`} · <a className="text-accent" href={href({ page:'policies' })}>{t('investigation.review')}</a></li>)}</ul></section>}
  </AppShell>;
};
