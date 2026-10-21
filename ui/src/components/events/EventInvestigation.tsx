import React, { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { apiClient, Event, EventCase, EventRuleDraft, EventRuleRequest, Policy } from '../../api/client';
import { useAuth } from '../../context/AuthContext';
import { canWritePolicies } from '../../auth/roles';
import { href } from '../../router';

export const EventInvestigation: React.FC<{ event: Event }> = ({ event }) => {
  const { t } = useTranslation(), { roles, scoped, policyPermissions } = useAuth();
  const [value, setValue] = useState<EventCase>(), [policy, setPolicy] = useState<Policy>();
  const [similar, setSimilar] = useState<Event[]>(), [total, setTotal] = useState(0), [draft, setDraft] = useState<EventRuleDraft>();
  const [dimension, setDimension] = useState<'country' | 'asn'>('country'), [action, setAction] = useState<'log' | 'block'>('log');
  const [busy, setBusy] = useState(false), [error, setError] = useState(false);
  const pendingCase = useRef<{ value: EventCase; id: string }>(), pendingRule = useRef<EventRuleRequest>();
  const allowed = canWritePolicies(roles) && (!scoped || !!policy?.id && !!policyPermissions?.[policy.id]?.includes('exceptions:write'));
  useEffect(() => {
    let active = true;
    apiClient.eventCase(event.block_id).then((v) => active && setValue(v)).catch(() => active && setError(true));
    apiClient.listPolicies().then((p) => active && setPolicy(p.find((v) => v.name === event.policy_id))).catch(() => active && setError(true));
    return () => { active = false; };
  }, [event.block_id, event.policy_id]);
  const run = async (f: () => Promise<void>) => { setBusy(true); setError(false); try { await f(); } catch { setError(true); } finally { setBusy(false); } };
  const save = () => run(async () => {
    if (!value) return;
    pendingCase.current ??= { value, id: crypto.randomUUID() };
    setValue(await apiClient.saveEventCase(pendingCase.current.value, pendingCase.current.id)); pendingCase.current = undefined;
  });
  const propose = () => run(async () => {
    if (!policy?.etag) return;
    pendingRule.current ??= { dimension, action, etag: policy.etag, request_id: crypto.randomUUID() };
    setDraft(await apiClient.proposeEventRule(event.block_id, pendingRule.current)); pendingRule.current = undefined;
  });
  const loadSimilar = () => run(async () => { const r = await apiClient.similarEvents(event.block_id); setSimilar(r.events); setTotal(r.total_matched); });
  const frozen = busy || !!pendingCase.current || !!pendingRule.current;
  return <section className="panel p-4 mb-4" aria-label={t('investigation.case')}>
    <h2 className="font-medium">{t('investigation.case')}</h2>
    {value && <div className="flex flex-wrap gap-3 mt-2 items-end">
      <label>{t('investigation.status')}<select className="field block" value={value.status} disabled={!allowed || frozen} onChange={(e) => setValue({ ...value, status: e.target.value as EventCase['status'] })}>{['open','investigating','resolved'].map((v) => <option key={v} value={v}>{t(`investigation.statuses.${v}`)}</option>)}</select></label>
      <label>{t('investigation.assignee')}<input className="field block" value={value.assignee} maxLength={256} disabled={!allowed || frozen} onChange={(e) => setValue({ ...value, assignee: e.target.value })}/></label>
      {allowed && <button className="btn" disabled={frozen} onClick={() => setValue({ ...value, assignee: '@me' })}>{t('investigation.claim')}</button>}
      {allowed && <label>{t('investigation.note')}<textarea className="field block" maxLength={1000} value={value.note} disabled={frozen} onChange={(e) => setValue({ ...value, note: e.target.value })}/></label>}
      {allowed && <button className="btn" disabled={busy || !!pendingRule.current} onClick={() => void save()}>{t('investigation.saveCase')}</button>}
    </div>}
    <p className="text-sm text-muted mt-2">{t('investigation.retention')}</p>
    <button className="btn mt-3" disabled={busy} onClick={() => void loadSimilar()}>{t('investigation.similar')}</button>
    {similar && <div className="mt-2"><p>{t('investigation.similarCount', { count: total })}</p>{similar.slice(0,20).map((v) => <a className="block text-accent font-mono" key={v.block_id} href={href({ page: 'event', blockId: v.block_id })}>{v.block_id}</a>)}</div>}
    {allowed && event.geoip_version && <div className="mt-3 flex gap-2 items-end flex-wrap">
      <label>{t('investigation.ruleDimension')}<select className="field block" value={dimension} disabled={frozen || !!draft} onChange={(e) => setDimension(e.target.value as 'country' | 'asn')}><option value="country">{t('investigation.country')}</option><option value="asn">ASN</option></select></label>
      <label>{t('investigation.action')}<select className="field block" value={action} disabled={frozen || !!draft} onChange={(e) => setAction(e.target.value as 'log' | 'block')}><option value="log">{t('investigation.log')}</option><option value="block">{t('investigation.block')}</option></select></label>
      <button className="btn" disabled={busy || !!pendingCase.current || !policy || !!draft} onClick={() => void propose()}>{t('investigation.propose')}</button>
      <p className="text-sm text-muted w-full">{t('investigation.draftHelp')}</p>
    </div>}
    {draft && <p role="status" className="mt-2">{t('investigation.draftCreated', { version: draft.policy_version })} <a className="text-accent" href={href({ page: 'policies' })}>{t('investigation.review')}</a></p>}
    {error && <p role="alert" className="mt-2">{t('investigation.error')}</p>}
  </section>;
};
