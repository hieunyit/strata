// A policy's geo rules (W19-G2-01, W19-F-01): countries and/or ASNs of the
// client address, block or log, optionally the addresses outside them.
// The control plane assigns the id of a new rule (sent as 0 or absent).
import type { components } from '../api/generated/admin';

export type GeoRule = components['schemas']['v1PolicyGeoRule'];
type Spec = components['schemas']['v1PolicySpec'];

export const MAX_GEO_RULES = 16;
const country = /^[A-Z]{2}$/;

/** The rule as the API stores it: sorted lists, no empty one. */
export function normalizeGeoRule(r: GeoRule): GeoRule {
  const out: GeoRule = { action: r.action === 'ACTION_LOG' ? 'ACTION_LOG' : 'ACTION_BLOCK' };
  if (r.id) out.id = r.id;
  const countries = [...new Set(r.countries ?? [])].sort();
  const asns = [...new Set(r.asns ?? [])].sort((a, b) => a - b);
  if (countries.length) out.countries = countries;
  if (asns.length) out.asns = asns;
  if (r.not) out.not = true;
  return out;
}

/** Reads "VN, us cn" into ISO codes; bad tokens are returned apart. */
export function parseCountries(text: string): { values: string[]; bad: string[] } {
  const values: string[] = [];
  const bad: string[] = [];
  for (const tok of text.split(/[\s,;]+/).filter(Boolean)) {
    const c = tok.toUpperCase();
    if (country.test(c)) values.push(c);
    else bad.push(tok);
  }
  return { values, bad };
}

/** Reads "7552, AS15169" into ASNs; bad tokens are returned apart. */
export function parseAsns(text: string): { values: number[]; bad: string[] } {
  const values: number[] = [];
  const bad: string[] = [];
  for (const tok of text.split(/[\s,;]+/).filter(Boolean)) {
    const m = /^(?:AS)?([1-9][0-9]{0,9})$/i.exec(tok);
    const n = m ? Number(m[1]) : NaN;
    if (Number.isInteger(n) && n > 0 && n <= 4294967295) values.push(n);
    else bad.push(tok);
  }
  return { values, bad };
}

/** One line for the diff and lists: "block VN, CN · AS7552", "log outside VN". */
export function geoRuleSummary(r: GeoRule): string {
  const parts = [...(r.countries ?? []), ...(r.asns ?? []).map((a) => `AS${a}`)];
  const action = r.action === 'ACTION_LOG' ? 'log' : 'block';
  return `${r.id ? `${r.id} ` : ''}${action}${r.not ? ' outside' : ''} ${parts.join(', ')}`.trim();
}

/** Whether a rule names something. */
export function geoRuleValid(r: GeoRule): boolean {
  return (r.countries?.length ?? 0) + (r.asns?.length ?? 0) > 0;
}

/**
 * The spec with a new rule blocking (or logging) one country or ASN, unless
 * a rule of the same action already names it. `added` is false when nothing
 * changed.
 */
export function withGeoRule(spec: Spec, target: { country?: string; asn?: number }, action: 'ACTION_BLOCK' | 'ACTION_LOG'): { spec: Spec; added: boolean } {
  const rules = spec.geo_rules ?? [];
  const has = rules.some(
    (r) =>
      !r.not &&
      (r.action ?? 'ACTION_BLOCK') === action &&
      ((target.country && r.countries?.includes(target.country)) || (target.asn && r.asns?.includes(target.asn))),
  );
  if (has) return { spec, added: false };
  if (rules.length >= MAX_GEO_RULES) throw new Error(`a policy has at most ${MAX_GEO_RULES} geo rules`);
  const rule: GeoRule = target.country ? { countries: [target.country], action } : { asns: [target.asn!], action };
  return { spec: { ...spec, geo_rules: [...rules, rule] }, added: true };
}
