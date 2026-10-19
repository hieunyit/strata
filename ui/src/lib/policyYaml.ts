// YAML view of a policy spec for the policy editor (W11-F-01). The keys
// and values are those of docs/spec/policies.schema.json (mode: shadow |
// enforce, oversize: pass | block, response...), the API carries them as
// enums (MODE_SHADOW...). Only that small shape is read: block mappings
// two levels deep, scalars, and string lists (flow [a, b] or block "- a").
// Anything else is an error with its line, never guessed.
import type { components } from '../api/generated/admin';

export type PolicySpec = components['schemas']['v1PolicySpec'];
type Mode = NonNullable<PolicySpec['mode']>;
type Oversize = NonNullable<PolicySpec['oversize']>;

const modeOut: Record<string, string> = { MODE_SHADOW: 'shadow', MODE_ENFORCE: 'enforce' };
const modeIn: Record<string, Mode> = { shadow: 'MODE_SHADOW', enforce: 'MODE_ENFORCE' };
const oversizeOut: Record<string, string> = { OVERSIZE_PASS: 'pass', OVERSIZE_BLOCK: 'block' };
const oversizeIn: Record<string, Oversize> = { pass: 'OVERSIZE_PASS', block: 'OVERSIZE_BLOCK' };
export const DATA_GUARDS = ['cccd', 'jwt', 'pan'] as const;

// specToYaml writes the canonical text of a spec: always the same text for
// the same spec, so form edits give a stable YAML view.
export function specToYaml(spec: PolicySpec): string {
  const lines = [`mode: ${modeOut[spec.mode ?? ''] ?? 'shadow'}`];
  if (spec.oversize && spec.oversize !== 'OVERSIZE_UNSPECIFIED') {
    lines.push(`oversize: ${oversizeOut[spec.oversize]}`);
  }
  if (spec.mode === 'MODE_ENFORCE' && validCanary(spec.canary_percent)) {
    lines.push(`canary_percent: ${spec.canary_percent}`);
  }
  const [enforce, shadow] = paranoiaLevels(spec);
  if (enforce > 1) lines.push(`crs_paranoia: ${enforce}`);
  if (shadow > enforce) lines.push(`crs_paranoia_shadow: ${shadow}`);
  const r = spec.response;
  const guards = (r?.data_guard ?? []).filter((g) => (DATA_GUARDS as readonly string[]).includes(g));
  if (r && (r.allowed_codes_check || r.db_errors || guards.length)) {
    lines.push('response:');
    if (r.allowed_codes_check) lines.push('  allowed_codes_check: true');
    if (r.db_errors) lines.push('  db_errors: true');
    if (guards.length) lines.push(`  data_guard: [${guards.join(', ')}]`);
  }
  return lines.join('\n') + '\n';
}

// Errors are codes (editor.yamlErr.<code> in the locales) with their
// arguments, so the editor shows them in the user's language.
export type YamlErrorCode =
  | 'tab' | 'indent' | 'keyValue' | 'twice' | 'mode' | 'oversize' | 'responseNext'
  | 'bool' | 'list' | 'guard' | 'guardTwice' | 'unknown' | 'modeRequired' | 'canary' | 'canaryMode'
  | 'paranoia' | 'paranoiaShadow';

// CRS paranoia levels (W17-S-01): rules up to crs_paranoia block, those
// above it up to crs_paranoia_shadow are only reported. Absent or 0 means
// level 1, and a shadow level equal to the enforced one.
export const PARANOIA_LEVELS = [1, 2, 3, 4] as const;
const validLevel = (v: number | undefined) => v === undefined || v === 0 || (Number.isInteger(v) && v >= 1 && v <= 4);
export function paranoiaLevels(spec: PolicySpec): [number, number] {
  const enforce = validLevel(spec.crs_paranoia) && spec.crs_paranoia ? spec.crs_paranoia : 1;
  const shadow = validLevel(spec.crs_paranoia_shadow) && (spec.crs_paranoia_shadow ?? 0) > enforce ? spec.crs_paranoia_shadow! : enforce;
  return [enforce, shadow];
}

// canary_percent (W12-G2-01): 0.01 to 99.99, two decimals; leaving it out
// means every client.
export function validCanary(v: number | undefined): v is number {
  return typeof v === 'number' && Number.isFinite(v) && v >= 0.01 && v <= 99.99 && Math.abs(v * 100 - Math.round(v * 100)) < 1e-6;
}

export interface YamlError {
  line: number; // 1-based
  code: YamlErrorCode;
  args?: Record<string, string>;
}

export type ParseResult = { spec: PolicySpec; error?: undefined } | { spec?: undefined; error: YamlError };

interface Line {
  n: number;
  indent: number;
  text: string;
}

function scalar(v: string): string {
  const s = v.trim();
  if ((s.startsWith('"') && s.endsWith('"') && s.length >= 2) || (s.startsWith("'") && s.endsWith("'") && s.length >= 2)) {
    return s.slice(1, -1);
  }
  return s;
}

function bool(v: string, n: number): boolean | YamlError {
  const s = scalar(v);
  if (s === 'true') return true;
  if (s === 'false') return false;
  return { line: n, code: 'bool', args: { value: s } };
}

function flowList(v: string, n: number): string[] | YamlError {
  const s = v.trim();
  if (!s.startsWith('[') || !s.endsWith(']')) return { line: n, code: 'list' };
  const inner = s.slice(1, -1).trim();
  return inner === '' ? [] : inner.split(',').map(scalar);
}

const isErr = (x: unknown): x is YamlError => typeof x === 'object' && x !== null && 'code' in x && 'line' in x;

// yamlToSpec reads the editor's YAML. Unknown keys are refused, as the
// compiler's schema does (additionalProperties: false).
export function yamlToSpec(text: string): ParseResult {
  const lines: Line[] = [];
  text.split('\n').forEach((raw, i) => {
    if (raw.includes('\t')) {
      lines.push({ n: i + 1, indent: -1, text: raw });
      return;
    }
    const noComment = raw.replace(/(^|\s)#.*$/, '');
    if (noComment.trim() === '') return;
    lines.push({ n: i + 1, indent: noComment.length - noComment.trimStart().length, text: noComment.trim() });
  });
  const spec: PolicySpec = {};
  const seen = new Set<string>();
  let canaryLine = 0;
  let shadowLine = 0;
  let i = 0;
  const fail = (line: number, code: YamlErrorCode, args?: Record<string, string>): ParseResult => ({
    error: { line, code, args },
  });

  while (i < lines.length) {
    const l = lines[i];
    if (l.indent < 0) return fail(l.n, 'tab');
    if (l.indent !== 0) return fail(l.n, 'indent');
    const m = /^([a-z_]+):(.*)$/.exec(l.text);
    if (!m) return fail(l.n, 'keyValue');
    const [, key, rest] = m;
    if (seen.has(key)) return fail(l.n, 'twice', { key });
    seen.add(key);
    i++;
    switch (key) {
      case 'mode': {
        const v = modeIn[scalar(rest)];
        if (!v) return fail(l.n, 'mode');
        spec.mode = v;
        break;
      }
      case 'oversize': {
        const v = oversizeIn[scalar(rest)];
        if (!v) return fail(l.n, 'oversize');
        spec.oversize = v;
        break;
      }
      case 'canary_percent': {
        const v = scalar(rest);
        const n = Number(v);
        if (v === '' || !validCanary(n)) return fail(l.n, 'canary');
        spec.canary_percent = n;
        canaryLine = l.n;
        break;
      }
      case 'crs_paranoia':
      case 'crs_paranoia_shadow': {
        const v = scalar(rest);
        const n = Number(v);
        if (!/^[1-4]$/.test(v)) return fail(l.n, 'paranoia', { key });
        if (key === 'crs_paranoia') spec.crs_paranoia = n;
        else {
          spec.crs_paranoia_shadow = n;
          shadowLine = l.n;
        }
        break;
      }
      case 'response': {
        if (rest.trim() !== '' && rest.trim() !== '{}') return fail(l.n, 'responseNext');
        const resp: NonNullable<PolicySpec['response']> = {};
        const rseen = new Set<string>();
        while (i < lines.length && lines[i].indent !== 0) {
          const c = lines[i];
          if (c.indent < 0) return fail(c.n, 'tab');
          const cm = /^([a-z_]+):(.*)$/.exec(c.text);
          if (!cm) return fail(c.n, 'keyValue');
          const [, ck, cv] = cm;
          if (rseen.has(ck)) return fail(c.n, 'twice', { key: ck });
          rseen.add(ck);
          i++;
          if (ck === 'allowed_codes_check' || ck === 'db_errors') {
            const b = bool(cv, c.n);
            if (isErr(b)) return { error: b };
            resp[ck] = b;
          } else if (ck === 'data_guard') {
            let list: string[] | YamlError;
            if (cv.trim() === '') {
              list = [];
              while (i < lines.length && lines[i].indent > c.indent && lines[i].text.startsWith('- ')) {
                list.push(scalar(lines[i].text.slice(2)));
                i++;
              }
            } else {
              list = flowList(cv, c.n);
            }
            if (isErr(list)) return { error: list };
            for (const g of list) {
              if (!(DATA_GUARDS as readonly string[]).includes(g)) return fail(c.n, 'guard', { value: g });
            }
            if (new Set(list).size !== list.length) return fail(c.n, 'guardTwice');
            resp.data_guard = list;
          } else {
            return fail(c.n, 'unknown', { key: `response.${ck}` });
          }
        }
        spec.response = resp;
        break;
      }
      default:
        return fail(l.n, 'unknown', { key });
    }
  }
  if (!spec.mode) return fail(1, 'modeRequired');
  if (canaryLine && spec.mode !== 'MODE_ENFORCE') return fail(canaryLine, 'canaryMode');
  if (shadowLine && (spec.crs_paranoia_shadow ?? 0) < (spec.crs_paranoia ?? 1)) return fail(shadowLine, 'paranoiaShadow');
  return { spec };
}

// normalized: the spec the API stores for the same content (what the form
// shows, what is sent on save).
export function normalizeSpec(spec: PolicySpec): PolicySpec {
  const out: PolicySpec = { ...spec, mode: spec.mode && spec.mode !== 'MODE_UNSPECIFIED' ? spec.mode : 'MODE_SHADOW' };
  delete out.oversize;
  delete out.canary_percent;
  delete out.response;
  delete out.crs_paranoia;
  delete out.crs_paranoia_shadow;
  // stored as the API stores them: level 1 and a shadow level equal to
  // the enforced one are left out
  const [enforce, shadow] = paranoiaLevels(spec);
  if (enforce > 1) out.crs_paranoia = enforce;
  if (shadow > enforce) out.crs_paranoia_shadow = shadow;
  if (spec.oversize && spec.oversize !== 'OVERSIZE_UNSPECIFIED') out.oversize = spec.oversize;
  // a canary only exists on an enforce policy
  if (out.mode === 'MODE_ENFORCE' && validCanary(spec.canary_percent)) out.canary_percent = spec.canary_percent;
  const r = spec.response;
  if (r) {
    const response = { ...r };
    if (!r.allowed_codes_check) delete response.allowed_codes_check;
    if (!r.db_errors) delete response.db_errors;
    if (!(r.data_guard?.length)) delete response.data_guard;
    if (Object.keys(response).length) out.response = response;
  }
  return out;
}

// The basic YAML form owns only these fields. Preserve the rest across edits;
// show them separately so the operator can review the full saved policy.
export function mergeYamlSpec(base: PolicySpec, editable: PolicySpec): PolicySpec {
  return normalizeSpec({ ...base, mode: editable.mode, oversize: editable.oversize,
    canary_percent: editable.canary_percent, response: editable.response,
    crs_paranoia: editable.crs_paranoia, crs_paranoia_shadow: editable.crs_paranoia_shadow });
}

export function advancedSpec(spec: PolicySpec): Record<string, unknown> {
  const out: Record<string, unknown> = { ...spec };
  for (const key of ['mode', 'oversize', 'canary_percent', 'response', 'crs_paranoia', 'crs_paranoia_shadow']) delete out[key];
  // Zero/empty values emitted by protojson are equivalent to an absent default.
  for (const [key, value] of Object.entries(out)) {
    if (value === 0 || value === null || value === '' || (Array.isArray(value) && !value.length)
      || (key === 'fail_on_findings' && ['FAIL_ON_FINDINGS_UNSPECIFIED', 'FAIL_ON_FINDINGS_PASS'].includes(String(value)))) delete out[key];
  }
  return out;
}
