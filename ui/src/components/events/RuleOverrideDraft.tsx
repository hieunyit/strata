import React, { useCallback, useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { ApiError, Event, GetEventResponse, Policy, apiClient } from '../../api/client';
import { canWritePolicies } from '../../auth/roles';
import { useAuth } from '../../context/AuthContext';
import { href } from '../../router';
import { normalizeSpec } from '../../lib/policyYaml';
import { MAX_REASON, RuleAction, actionOf, setOverride, validReason } from '../../lib/ruleSets';

type Failure = 'load' | 'conflict' | 'invalid' | 'forbidden' | 'failed';
const ACTIONS: RuleAction[] = ['POLICY_RULE_ACTION_LOG', 'POLICY_RULE_ACTION_OFF', 'POLICY_RULE_ACTION_BLOCK'];

// RS-4b: "override this rule" for a whole policy, from an event or from
// the Rules & packs page (an exception is the narrow way: one route, one
// field). Saving makes a new DRAFT version of the policy, reviewed and
// deployed as any edit.
// policyName: the event's policy; without it, the form lists the policies
// to choose from (Rules & packs page).
export const OverrideForm: React.FC<{ policyName?: string; ruleIds: number[]; names: Record<number, string>; onClose: () => void }> = ({ policyName, ruleIds, names, onClose }) => {
  const { t } = useTranslation();
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [chosen, setChosen] = useState(policyName ?? '');
  const [policy, setPolicy] = useState<Policy>();
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<Failure>();
  const [rule, setRule] = useState(ruleIds[0]);
  const [action, setAction] = useState<RuleAction>('POLICY_RULE_ACTION_LOG');
  const [reason, setReason] = useState('');
  const [saved, setSaved] = useState<number>();
  const alive = useRef(false);
  const load = useCallback(async () => {
    setLoading(true); setPolicy(undefined); setError(undefined);
    try {
      const all = await apiClient.listPolicies();
      if (!alive.current) return;
      setPolicies(all);
      if (!chosen) return;
      const matches = all.filter((p) => p.name === chosen);
      if (matches.length !== 1 || !matches[0].id || !matches[0].etag) throw new Error('unavailable');
      setPolicy(matches[0]);
    } catch {
      if (alive.current) setError('load');
    } finally {
      if (alive.current) setLoading(false);
    }
  }, [chosen]);
  useEffect(() => { alive.current = true; void load(); return () => { alive.current = false; }; }, [load]);

  const current = policy?.spec?.rule_overrides?.find((o) => o.rule === rule);
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!policy?.id || !policy.etag || !validReason(reason) || saving) return;
    setSaving(true); setError(undefined);
    try {
      const spec = setOverride(normalizeSpec(policy.spec ?? {}), rule, { action, reason: reason.trim() });
      const next = await apiClient.updatePolicy(policy.id, spec, policy.etag);
      if (alive.current) setSaved(next.version);
    } catch (cause) {
      if (!alive.current) return;
      if (cause instanceof ApiError && cause.code === 409) { setPolicy(undefined); setError('conflict'); }
      else if (cause instanceof ApiError && cause.code === 400) setError('invalid');
      else if (cause instanceof ApiError && cause.code === 403) setError('forbidden');
      else setError('failed');
    } finally {
      if (alive.current) setSaving(false);
    }
  };

  return <section className="panel mb-5 p-4" aria-labelledby="override-heading" data-testid="override-form"
    onKeyDown={(e) => { if (e.key === 'Escape' && !saving) onClose(); }}>
    <h2 id="override-heading" className="font-medium">{t('ruleOverride.title')}</h2>
    {saved !== undefined ? <div role="status" className="mt-3 text-sm" data-testid="override-created">
      <p>{t('ruleOverride.created', { version: saved })}</p>
      <p className="mt-2 text-muted">{t('ruleOverride.reviewRequired')}</p>
      <a href={href({ page: 'policies' })} className="btn mt-3">{t('exception.viewPolicies')}</a>
      <button type="button" className="btn ml-2" onClick={onClose}>{t('exception.close')}</button>
    </div> : <form onSubmit={(e) => void submit(e)}>
      <p className="my-2 text-sm text-muted">{t('ruleOverride.help')}</p>
      {policyName === undefined && <label className="block text-sm">{t('ruleOverride.policy')}
        <select className="field mt-1 w-full" value={chosen} disabled={saving} onChange={(e) => setChosen(e.target.value)} data-testid="override-policy">
          <option value="">{t('ruleOverride.choosePolicy')}</option>
          {policies.map((p) => <option key={p.id} value={p.name}>{p.name}</option>)}
        </select>
      </label>}
      {policy && <p className="mt-2 text-sm text-muted">{t('exception.policyVersion', { name: policy.name, version: policy.version ?? '?' })}</p>}
      <div className="mt-3 grid gap-3 sm:grid-cols-2">
        <label className="min-w-0 text-sm">{t('ruleOverride.rule')}
          <select className="field mt-1 w-full" value={rule} disabled={saving} onChange={(e) => setRule(Number(e.target.value))} data-testid="override-rule">
            {ruleIds.map((id) => <option key={id} value={id}>{id}{names[id] ? ` · ${names[id]}` : ''}</option>)}
          </select>
        </label>
        <label className="min-w-0 text-sm">{t('ruleOverride.action')}
          <select className="field mt-1 w-full" value={action} disabled={saving} onChange={(e) => setAction(e.target.value as RuleAction)} data-testid="override-action">
            {ACTIONS.map((a) => <option key={a} value={a}>{t(`editor.ruleSets.action.${actionOf(a)}`)}</option>)}
          </select>
        </label>
      </div>
      {current && <p className="mt-2 text-sm text-muted" data-testid="override-current">
        {t('ruleOverride.current', { action: t(`editor.ruleSets.action.${actionOf(current.action)}`), reason: current.reason ?? '' })}
      </p>}
      <label className="mt-3 block text-sm">{t('ruleOverride.reason')}
        <textarea className="field mt-1 min-h-20 w-full py-2" value={reason} maxLength={MAX_REASON} disabled={saving} onChange={(e) => setReason(e.target.value)} data-testid="override-reason" />
      </label>
      {loading && <p role="status" className="mt-2 text-sm">{t('exception.loading')}</p>}
      {error && <p role="alert" className="mt-2 text-sm text-block">{t(`ruleOverride.errors.${error}`)}</p>}
      {(error === 'load' || error === 'conflict') && <button type="button" className="btn mt-2" disabled={loading} onClick={() => void load()}>{t('exception.reload')}</button>}
      <div className="mt-4 flex gap-2">
        <button type="submit" className="btn-primary" disabled={loading || saving || !policy || !validReason(reason) || error === 'forbidden'} data-testid="override-save">
          {t(saving ? 'exception.saving' : 'ruleOverride.save')}
        </button>
        <button type="button" className="btn" disabled={saving} onClick={onClose}>{t('exception.cancel')}</button>
      </div>
    </form>}
  </section>;
};

export const RuleOverrideDraft: React.FC<{ event: Event; rules?: GetEventResponse['rules'] }> = ({ event, rules }) => {
  const { roles } = useAuth();
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  // detection rules of the event, once each (not the policy's geo rules
  // nor protocol limits, which no override reaches)
  const ruleIds = [...new Set((event.violations ?? []).map((v) => v.rule_id))]
    .filter((id) => rules?.[String(id)]?.layer === 'managed');
  if (!canWritePolicies(roles) || !event.policy_id || ruleIds.length === 0) return null;
  const names = Object.fromEntries(ruleIds.map((id) => [id, rules?.[String(id)]?.name ?? '']));
  return <>
    <button type="button" className="btn mb-3 ml-2" disabled={open} aria-expanded={open} onClick={() => setOpen(true)} data-testid="override-open">{t('ruleOverride.open')}</button>
    {open && <OverrideForm policyName={event.policy_id} ruleIds={ruleIds} names={names} onClose={() => setOpen(false)} />}
  </>;
};
