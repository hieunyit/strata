import React, { useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { ListFilter, Plus, Trash2, X } from 'lucide-react';
import { EffectiveRules, RuleSet, RuleSetRules, apiClient } from '../../api/client';
import { PolicySpec, paranoiaLevels } from '../../lib/policyYaml';
import {
  MAX_REASON, MAX_RULE_OVERRIDES, RULE_ACTIONS, RuleAction, SET_GROUPS, actionOf, draftOf, filterSummary, refreshCustomSet, sameFilter, setOverride, setRuleSet, setTitle, validReason, validRuleId,
} from '../../lib/ruleSets';

// Rule sets and overrides of a policy (RS-4, NGINX Instance Manager
// style): built-in sets by group, each on or off with an action; the rules
// of a set, each overridable with a reason; every override of the policy;
// and what the draft changes, resolved by the control plane before saving.
export const RuleSetsEditor: React.FC<{ spec: PolicySpec; onChange: (spec: PolicySpec) => void; policyName?: string }> = ({ spec, onChange, policyName = '' }) => {
  const { t, i18n } = useTranslation();
  const [tab, setTab] = useState<'sets' | 'overrides'>('sets');
  const [sets, setSets] = useState<RuleSet[] | undefined>();
  const [catalog, setCatalog] = useState(true);
  const [loadError, setLoadError] = useState(false);
  const [open, setOpen] = useState<string | undefined>();

  useEffect(() => {
    const ac = new AbortController();
    apiClient.listRuleSets(ac.signal, policyName).then(
      (r) => {
        setSets(r.sets);
        setCatalog(r.catalog_available);
      },
      () => !ac.signal.aborted && setLoadError(true),
    );
    return () => ac.abort();
  }, [policyName]);

  const chosen = useMemo(() => new Map((spec.rule_sets ?? []).map((r) => [r.set ?? '', r.action ?? 'POLICY_RULE_ACTION_UNSPECIFIED'])), [spec.rule_sets]);
  const copies = useMemo(() => new Map((spec.rule_sets ?? []).filter((r) => r.match).map((r) => [r.set ?? '', r.match])), [spec.rule_sets]);
  const overrides = spec.rule_overrides ?? [];
  const tabButton = (id: 'sets' | 'overrides', label: string) => (
    <button
      type="button"
      role="tab"
      aria-selected={tab === id}
      className={`px-3 py-1.5 text-[13px] border-b-2 ${tab === id ? 'border-accent font-medium' : 'border-transparent text-muted'}`}
      onClick={() => setTab(id)}
      data-testid={`rulesets-tab-${id}`}
    >
      {label}
    </button>
  );

  return (
    <fieldset className="min-w-0 space-y-2 text-[13px]" data-testid="editor-rule-sets">
      <legend className="label">{t('editor.ruleSets.title')}</legend>
      <p className="text-xs text-muted">{t('editor.ruleSets.note')}</p>
      <Impact spec={spec} />
      <div role="tablist" className="flex gap-1 border-b border-line">
        {tabButton('sets', t('editor.ruleSets.tabSets'))}
        {tabButton('overrides', t('editor.ruleSets.tabOverrides', { count: overrides.length }))}
      </div>
      {tab === 'sets' && (
        <div className="space-y-3" role="tabpanel">
          {loadError && <p className="text-xs text-block" role="alert">{t('editor.ruleSets.loadError')}</p>}
          {!sets && !loadError && <p className="text-xs text-muted">{t('common.loading')}</p>}
          {sets && !catalog && <p className="text-xs text-muted" data-testid="rulesets-no-catalog">{t('editor.ruleSets.noCatalog')}</p>}
          {sets && SET_GROUPS.map((g) => {
            const inGroup = sets.filter((s) => s.group === g);
            if (!inGroup.length) return null;
            return (
              <div key={g} data-testid={`rulesets-group-${g}`}>
                <h4 className="text-xs font-medium uppercase tracking-wide text-muted mb-1">{t(`editor.ruleSets.group.${g}`)}</h4>
                <ul className="divide-y divide-line rounded-md border border-line">
                  {inGroup.map((s) => {
                    const on = chosen.has(s.name);
                    return (
                      <li key={s.name} className="p-2" data-testid={`ruleset-${s.name}`}>
                        <div className="flex flex-wrap items-center gap-2">
                          <label className="flex min-w-0 flex-1 basis-full items-center gap-1.5 sm:basis-0">
                            <input
                              type="checkbox"
                              checked={on}
                              onChange={(e) => onChange(setRuleSet(spec, sets, s.name, e.target.checked ? 'POLICY_RULE_ACTION_LOG' : undefined))}
                              data-testid={`ruleset-on-${s.name}`}
                            />
                            <span className="truncate">{setTitle(s, i18n.language)}</span>
                            {s.class && <span className={`rounded-full border border-line px-1.5 text-[11px] ${s.class === 'malicious' ? 'text-block' : 'text-muted'}`}>{t(`editor.ruleSets.class.${s.class}`)}</span>}
                          </label>
                          <span className="text-xs text-muted tabular-nums" data-testid={`ruleset-count-${s.name}`}>
                            {s.rule_count === undefined ? '—' : t('editor.ruleSets.rules', { count: s.rule_count })}
                            {s.matches_24h !== undefined && <span className={s.matches_24h ? ' text-ink' : ''} data-testid={`ruleset-matches-${s.name}`}> · {t('editor.ruleSets.matches', { count: s.matches_24h })}</span>}
                          </span>
                          <select
                            className="field w-auto"
                            disabled={!on}
                            value={chosen.get(s.name) ?? 'POLICY_RULE_ACTION_UNSPECIFIED'}
                            onChange={(e) => onChange(setRuleSet(spec, sets, s.name, e.target.value as RuleAction))}
                            aria-label={t('editor.ruleSets.actionOf', { name: setTitle(s, i18n.language) })}
                            data-testid={`ruleset-action-${s.name}`}
                          >
                            {RULE_ACTIONS.map((a) => <option key={a} value={a}>{t(`editor.ruleSets.action.${actionOf(a)}`)}</option>)}
                          </select>
                          <button
                            type="button"
                            className="btn"
                            disabled={!catalog || !s.rule_count}
                            onClick={() => setOpen(open === s.name ? undefined : s.name)}
                            aria-expanded={open === s.name}
                            data-testid={`ruleset-view-${s.name}`}
                          >
                            <ListFilter className="w-3.5 h-3.5" />
                            {t('editor.ruleSets.view')}
                          </button>
                        </div>
                        {/* RS-3c: the policy runs the copy it was saved with */}
                        {s.custom && copies.has(s.name) && !sameFilter(copies.get(s.name), s.match) && (
                          <p className="mt-1 text-xs text-muted" data-testid={`ruleset-stale-${s.name}`}>
                            {t('editor.ruleSets.staleCopy', { version: s.version ?? '?' })}
                            <button type="button" className="ml-2 underline" onClick={() => onChange(refreshCustomSet(spec, s.name))} data-testid={`ruleset-refresh-${s.name}`}>{t('editor.ruleSets.useCurrent')}</button>
                          </p>
                        )}
                        {s.custom && chosen.has(s.name) && !copies.has(s.name) && <p className="mt-1 text-xs text-muted">{t('editor.ruleSets.copyOnSave')}</p>}
                        {open === s.name && <SetRules set={s.name} spec={spec} onChange={onChange} onClose={() => setOpen(undefined)} />}
                      </li>
                    );
                  })}
                </ul>
              </div>
            );
          })}
          {/* sets the catalog does not know (an older or newer control plane) */}
          {sets && [...chosen.keys()].filter((n) => !sets.some((s) => s.name === n)).map((n) => (
            <p key={n} className="text-xs text-block" data-testid="ruleset-unknown">
              {copies.has(n) ? t('editor.ruleSets.deletedCustom', { name: n, filter: filterSummary(copies.get(n)) }) : t('editor.ruleSets.unknown', { name: n })}
              <button type="button" className="ml-2 underline" onClick={() => onChange(setRuleSet(spec, sets, n, undefined))}>{t('editor.ruleSets.remove')}</button>
            </p>
          ))}
        </div>
      )}
      {tab === 'overrides' && <Overrides spec={spec} onChange={onChange} />}
    </fieldset>
  );
};

const ActionSelect: React.FC<{ value: RuleAction | undefined; onChange: (a: RuleAction) => void; label: string; testId: string }> = ({ value, onChange, label, testId }) => {
  const { t } = useTranslation();
  return (
    <select className="field w-auto" value={value ?? 'POLICY_RULE_ACTION_UNSPECIFIED'} onChange={(e) => onChange(e.target.value as RuleAction)} aria-label={label} data-testid={testId}>
      {RULE_ACTIONS.map((a) => <option key={a} value={a}>{t(`editor.ruleSets.action.${actionOf(a)}`)}</option>)}
    </select>
  );
};

const ReasonInput: React.FC<{ value: string | undefined; onChange: (r: string) => void; testId: string }> = ({ value, onChange, testId }) => {
  const { t } = useTranslation();
  return (
    <input
      className="field min-w-0 flex-1"
      placeholder={t('editor.ruleSets.reason')}
      aria-label={t('editor.ruleSets.reason')}
      maxLength={MAX_REASON}
      value={value ?? ''}
      aria-invalid={!validReason(value)}
      onChange={(e) => onChange(e.target.value)}
      data-testid={testId}
    />
  );
};

// The rules of one set, searchable, each overridable for this policy.
const SetRules: React.FC<{ set: string; spec: PolicySpec; onChange: (spec: PolicySpec) => void; onClose: () => void }> = ({ set, spec, onChange, onClose }) => {
  const { t } = useTranslation();
  const [q, setQ] = useState('');
  const [page, setPage] = useState<RuleSetRules | undefined>();
  const [error, setError] = useState(false);
  useEffect(() => {
    const ac = new AbortController();
    const timer = setTimeout(() => {
      apiClient.listRuleSetRules(set, q.trim(), 0, ac.signal).then(
        (r) => { setPage(r); setError(false); },
        () => !ac.signal.aborted && setError(true),
      );
    }, 250);
    return () => { clearTimeout(timer); ac.abort(); };
  }, [set, q]);
  const byRule = new Map((spec.rule_overrides ?? []).map((o) => [o.rule ?? 0, o]));
  return (
    <div className="mt-2 rounded-md bg-sunken p-2 space-y-2" data-testid={`ruleset-rules-${set}`}>
      <div className="flex items-center gap-2">
        <input className="field flex-1" placeholder={t('editor.ruleSets.search')} aria-label={t('editor.ruleSets.search')} value={q} maxLength={64} onChange={(e) => setQ(e.target.value)} data-testid="ruleset-search" />
        <button type="button" className="text-muted" onClick={onClose} aria-label={t('editor.ruleSets.close')}><X className="h-4 w-4" /></button>
      </div>
      {error && <p className="text-xs text-block" role="alert">{t('editor.ruleSets.loadError')}</p>}
      {page && (
        <>
          <p className="text-xs text-muted" role="status">{t('editor.ruleSets.shown', { shown: page.rules.length, total: page.total })}</p>
          <ul className="max-h-80 overflow-y-auto divide-y divide-line">
            {page.rules.map((r) => {
              const o = byRule.get(r.id);
              return (
                <li key={r.id} className="py-1.5 space-y-1" data-testid="ruleset-rule">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-xs">{r.id}</span>
                    <span className="min-w-0 flex-1 basis-3/4 truncate sm:basis-0" title={r.name}>{r.name}</span>
                    {r.severity && <span className="rounded-full border border-line px-1.5 text-[11px] text-muted">{r.severity}</span>}
                    <ActionSelect
                      value={o?.action}
                      label={t('editor.ruleSets.overrideOf', { rule: r.id })}
                      onChange={(a) => onChange(o || a !== 'POLICY_RULE_ACTION_UNSPECIFIED' ? setOverride(spec, r.id, { action: a }) : spec)}
                      testId={`ruleset-rule-action-${r.id}`}
                    />
                    {o && (
                      <button type="button" className="text-muted hover:text-block" aria-label={t('editor.ruleSets.removeOverride', { rule: r.id })} onClick={() => onChange(setOverride(spec, r.id, undefined))}>
                        <Trash2 className="h-4 w-4" />
                      </button>
                    )}
                  </div>
                  {o && <div className="flex"><ReasonInput value={o.reason} onChange={(reason) => onChange(setOverride(spec, r.id, { reason }))} testId={`ruleset-rule-reason-${r.id}`} /></div>}
                </li>
              );
            })}
          </ul>
          {page.next_cursor > 0 && <p className="text-xs text-muted">{t('editor.ruleSets.more')}</p>}
        </>
      )}
    </div>
  );
};

// Every override of the policy, and a new one by Rule ID.
const Overrides: React.FC<{ spec: PolicySpec; onChange: (spec: PolicySpec) => void }> = ({ spec, onChange }) => {
  const { t } = useTranslation();
  const list = spec.rule_overrides ?? [];
  const [rule, setRule] = useState('');
  const [action, setAction] = useState<RuleAction>('POLICY_RULE_ACTION_OFF');
  const [reason, setReason] = useState('');
  const id = Number(rule.trim());
  const exists = list.some((o) => o.rule === id);
  const canAdd = rule.trim() !== '' && validRuleId(id) && !exists && validReason(reason) && list.length < MAX_RULE_OVERRIDES;
  const add = () => {
    onChange(setOverride(spec, id, { action, reason: reason.trim() }));
    setRule('');
    setReason('');
  };
  return (
    <div className="space-y-2" role="tabpanel" data-testid="rulesets-overrides">
      <p className="text-xs text-muted">{t('editor.ruleSets.overridesNote')}</p>
      {list.length === 0 && <p className="text-xs text-muted" data-testid="overrides-empty">{t('editor.ruleSets.noOverrides')}</p>}
      <ul className="space-y-1.5">
        {list.map((o) => (
          <li key={o.rule} className="flex flex-wrap items-center gap-2 rounded-md border border-line p-2" data-testid="override-row">
            <span className="font-mono text-xs w-20">{o.rule}</span>
            <ActionSelect value={o.action} label={t('editor.ruleSets.overrideOf', { rule: o.rule })} onChange={(a) => onChange(setOverride(spec, o.rule ?? 0, { action: a }))} testId={`override-action-${o.rule}`} />
            <ReasonInput value={o.reason} onChange={(r) => onChange(setOverride(spec, o.rule ?? 0, { reason: r }))} testId={`override-reason-${o.rule}`} />
            <button type="button" className="text-muted hover:text-block" aria-label={t('editor.ruleSets.removeOverride', { rule: o.rule })} onClick={() => onChange(setOverride(spec, o.rule ?? 0, undefined))} data-testid={`override-remove-${o.rule}`}>
              <Trash2 className="h-4 w-4" />
            </button>
          </li>
        ))}
      </ul>
      <div className="flex flex-wrap items-center gap-2 rounded-md border border-dashed border-line p-2">
        <input className="field w-28 font-mono" inputMode="numeric" placeholder={t('editor.ruleSets.ruleId')} aria-label={t('editor.ruleSets.ruleId')} value={rule} onChange={(e) => setRule(e.target.value)} data-testid="override-new-rule" />
        <ActionSelect value={action} label={t('editor.ruleSets.newAction')} onChange={setAction} testId="override-new-action" />
        <ReasonInput value={reason} onChange={setReason} testId="override-new-reason" />
        <button type="button" className="btn" disabled={!canAdd} onClick={add} data-testid="override-add">
          <Plus className="w-3.5 h-3.5" />
          {t('editor.ruleSets.add')}
        </button>
        {exists && <p className="w-full text-xs text-block">{t('editor.ruleSets.exists', { rule: id })}</p>}
      </div>
    </div>
  );
};

// What the draft does to the rules: counts by action, and the rules whose
// action is not their own.
const Impact: React.FC<{ spec: PolicySpec }> = ({ spec }) => {
  const { t } = useTranslation();
  const draft = useMemo(() => draftOf(spec, paranoiaLevels(spec)), [spec]);
  const key = JSON.stringify(draft);
  const [result, setResult] = useState<EffectiveRules | undefined>();
  const [unavailable, setUnavailable] = useState(false);
  const [show, setShow] = useState(false);
  useEffect(() => {
    const ac = new AbortController();
    const timer = setTimeout(() => {
      apiClient.resolveRuleActions(JSON.parse(key), { changed: true }, ac.signal).then(
        (r) => { setResult(r); setUnavailable(false); },
        () => !ac.signal.aborted && setUnavailable(true),
      );
    }, 400);
    return () => { clearTimeout(timer); ac.abort(); };
  }, [key]);
  if (unavailable) return <p className="text-xs text-muted" data-testid="rulesets-impact-unavailable">{t('editor.ruleSets.impactUnavailable')}</p>;
  if (!result) return null;
  const c = result.counts;
  return (
    <div className="rounded-md border border-line p-2 text-xs" data-testid="rulesets-impact">
      <p role="status">
        {t('editor.ruleSets.impact', { block: c.block ?? 0, log: c.log ?? 0, off: c.off ?? 0, score: c.score ?? 0 })}{' '}
        {result.total > 0 && (
          <button type="button" className="underline" onClick={() => setShow(!show)} aria-expanded={show} data-testid="rulesets-changed">
            {t('editor.ruleSets.changed', { count: result.total })}
          </button>
        )}
      </p>
      {show && (
        <ul className="mt-1 max-h-64 overflow-y-auto divide-y divide-line" data-testid="rulesets-changed-list">
          {result.rules.map((r) => (
            <li key={r.id} className="flex flex-wrap gap-2 py-1">
              <span className="font-mono">{r.id}</span>
              <span className="min-w-0 flex-1 truncate" title={r.name}>{r.name}</span>
              <span>{t(`editor.ruleSets.effective.${r.own}`)} → <strong>{t(`editor.ruleSets.effective.${r.action}`)}</strong></span>
              <span className="text-muted">{r.source === 'set' ? r.set : t(`editor.ruleSets.source.${r.source}`)}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
};
