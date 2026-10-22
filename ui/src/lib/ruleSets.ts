// Rule sets and rule overrides of a policy (RS-4, docs/plan/rule-sets.md):
// built-in sets of rules (filters on the rules' metadata) given an action,
// and single rules given an action with a reason. Edited in the form only,
// like geo rules: the YAML view leaves them out and keeps them on edits.
import type { RuleActionsDraft, RuleSet } from '../api/client';
import type { PolicySpec } from './policyYaml';

export type RuleSetRef = NonNullable<PolicySpec['rule_sets']>[number];
export type RuleOverride = NonNullable<PolicySpec['rule_overrides']>[number];
export type RuleAction = NonNullable<RuleSetRef['action']>;

// the actions a set or an override can give, in the order the form lists
// them; UNSPECIFIED is the rule's own behaviour ("default")
export const RULE_ACTIONS: RuleAction[] = ['POLICY_RULE_ACTION_BLOCK', 'POLICY_RULE_ACTION_LOG', 'POLICY_RULE_ACTION_OFF', 'POLICY_RULE_ACTION_UNSPECIFIED'];
export const MAX_RULE_SETS = 32;
export const MAX_RULE_OVERRIDES = 2048;
export const MAX_REASON = 256;
export const SET_GROUPS = ['attack', 'signature', 'technology', 'bot', 'custom'] as const;

const actionWord: Record<RuleAction, string> = {
  POLICY_RULE_ACTION_UNSPECIFIED: 'default',
  POLICY_RULE_ACTION_OFF: 'off',
  POLICY_RULE_ACTION_LOG: 'log',
  POLICY_RULE_ACTION_BLOCK: 'block',
};
export const actionOf = (a: RuleAction | undefined): string => actionWord[a ?? 'POLICY_RULE_ACTION_UNSPECIFIED'];

// as the API stores them: no empty lists, the default action left out,
// overrides by rule
export function normalizeRuleActions(spec: PolicySpec): PolicySpec {
  const out: PolicySpec = { ...spec };
  delete out.rule_sets;
  delete out.rule_overrides;
  const bare = <T extends { action?: RuleAction }>(x: T): T => {
    const y = { ...x };
    if (!y.action || y.action === 'POLICY_RULE_ACTION_UNSPECIFIED') delete y.action;
    return y;
  };
  if (spec.rule_sets?.length) out.rule_sets = spec.rule_sets.map(bare);
  if (spec.rule_overrides?.length) out.rule_overrides = [...spec.rule_overrides].map(bare).sort((a, b) => (a.rule ?? 0) - (b.rule ?? 0));
  return out;
}

// setRuleSet turns set `name` on with `action`, or off (undefined). The
// list follows the catalog's order, where a later set wins over an
// earlier one for a rule in both (bots-trusted last); sets the catalog
// does not know keep their place at the end.
export function setRuleSet(spec: PolicySpec, catalog: RuleSet[], name: string, action: RuleAction | undefined): PolicySpec {
  const current = new Map((spec.rule_sets ?? []).map((r) => [r.set ?? '', r]));
  // a custom set keeps the copy of its filter the policy was saved with
  if (action === undefined) current.delete(name);
  else current.set(name, { ...current.get(name), set: name, action });
  const known = catalog.map((s) => s.name);
  const ordered = known.filter((n) => current.has(n)).map((n) => current.get(n)!);
  const rest = (spec.rule_sets ?? []).filter((r) => !known.includes(r.set ?? '') && current.has(r.set ?? ''));
  return normalizeRuleActions({ ...spec, rule_sets: [...ordered, ...rest] });
}

// setOverride gives rule `rule` an action (keeping its reason), or removes
// its override (undefined).
export function setOverride(spec: PolicySpec, rule: number, patch: Partial<RuleOverride> | undefined): PolicySpec {
  const list = spec.rule_overrides ?? [];
  if (patch === undefined) return normalizeRuleActions({ ...spec, rule_overrides: list.filter((o) => o.rule !== rule) });
  const found = list.find((o) => o.rule === rule);
  const next = found ? list.map((o) => (o.rule === rule ? { ...o, ...patch } : o)) : [...list, { rule, reason: '', ...patch }];
  return normalizeRuleActions({ ...spec, rule_overrides: next });
}

export const validRuleId = (n: number): boolean => Number.isInteger(n) && n >= 1 && n <= 0xffffffff;
export const validReason = (r: string | undefined): boolean => !!r && r.trim().length > 0 && r.length <= MAX_REASON;

// what the control plane refuses on save: every override needs a reason
export function ruleActionsValid(spec: PolicySpec): boolean {
  return (spec.rule_sets?.length ?? 0) <= MAX_RULE_SETS && (spec.rule_overrides?.length ?? 0) <= MAX_RULE_OVERRIDES &&
    (spec.rule_overrides ?? []).every((o) => validRuleId(o.rule ?? 0) && validReason(o.reason));
}

// the body of POST /v1/rule-sets:resolve for this spec at its paranoia
// levels (policyYaml.paranoiaLevels); incomplete overrides (no reason
// yet) are left out so the preview still works
export function draftOf(spec: PolicySpec, [enforce, shadow]: [number, number]): RuleActionsDraft {
  const d: RuleActionsDraft = {};
  if (enforce > 1) d.crs_paranoia = enforce;
  if (shadow > enforce) d.crs_paranoia_shadow = shadow;
  const sets = (spec.rule_sets ?? []).map((r) => ({ set: r.set ?? '', action: actionOf(r.action) as 'off' | 'log' | 'block' | 'default', ...(r.match ? { match: r.match } : {}) }));
  if (sets.length) d.rule_sets = sets;
  const overrides = (spec.rule_overrides ?? []).filter((o) => validReason(o.reason))
    .map((o) => ({ rule: o.rule ?? 0, action: actionOf(o.action) as 'off' | 'log' | 'block' | 'default', reason: o.reason ?? '' }));
  if (overrides.length) d.rule_overrides = overrides;
  return d;
}

export function setTitle(s: Pick<RuleSet, 'title' | 'name'>, language: string): string {
  return (language.startsWith('vi') ? s.title.vi : s.title.en) || s.title.en || s.name;
}

// RS-3c: custom sets (custom-*), whose filter a policy copies when saved.
export const isCustomSet = (name: string): boolean => /^custom-[a-z0-9][a-z0-9-]{0,47}$/.test(name);

type Filter = { sources?: string[]; attack_types?: string[]; tags?: string[]; ids?: number[] };
const sorted = (l?: (string | number)[]) => [...(l ?? [])].map(String).sort();

// sameFilter: two filters select the same rules (order does not count).
export function sameFilter(a: Filter | undefined, b: Filter | undefined): boolean {
  return (['sources', 'attack_types', 'tags', 'ids'] as const).every((k) => JSON.stringify(sorted(a?.[k])) === JSON.stringify(sorted(b?.[k])));
}

// filterSummary: a filter in one line, for the diff and the lists.
export function filterSummary(f: Filter | undefined): string {
  if (!f) return '';
  const parts: string[] = [];
  if (f.sources?.length) parts.push(`sources=${f.sources.join(',')}`);
  if (f.attack_types?.length) parts.push(`attack_types=${f.attack_types.join(',')}`);
  if (f.tags?.length) parts.push(`tags=${f.tags.join(',')}`);
  if (f.ids?.length) parts.push(`ids=${f.ids.join(',')}`);
  return parts.join(' ');
}

// refreshCustomSet drops the copy of set name's filter: the policy takes
// the set's current filter when saved.
export function refreshCustomSet(spec: PolicySpec, name: string): PolicySpec {
  return normalizeRuleActions({ ...spec, rule_sets: (spec.rule_sets ?? []).map((r) => {
    if (r.set !== name) return r;
    const out = { ...r };
    delete out.match;
    return out;
  }) });
}
