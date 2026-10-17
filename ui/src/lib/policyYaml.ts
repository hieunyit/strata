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
export const DATA_GUARDS = ['cccd', 'jwt'] as const;

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
  const r = spec.response;
  const guards = (r?.data_guard ?? []).filter((g) => (DATA_GUARDS as readonly string[]).includes(g));
  if (r && (r.allowed_codes_check || r.db_errors || guards.length)) {
    lines.push('response:');
    if (r.allowed_codes_check) lines.push('  allowed_codes_check: true');
    if (r.db_errors) lines.push('  db_errors: true');
    if (guards.length) lines.push(`  data_guard: [${guards.join(', ')}]`);
  }
  const g = (spec as any).geo_restrictions;
  if (g) {
    lines.push('geo_restrictions:');
    if (g.enabled !== undefined) lines.push(`  enabled: ${g.enabled ? 'true' : 'false'}`);
    if (g.default_action) lines.push(`  default_action: ${g.default_action}`);
    if (g.blocked_countries?.length) lines.push(`  blocked_countries: [${g.blocked_countries.join(', ')}]`);
    if (g.challenged_countries?.length) lines.push(`  challenged_countries: [${g.challenged_countries.join(', ')}]`);
    if (g.blocked_asns?.length) lines.push(`  blocked_asns: [${g.blocked_asns.join(', ')}]`);
    if (g.challenged_asns?.length) lines.push(`  challenged_asns: [${g.challenged_asns.join(', ')}]`);
    if (g.exempt_ips?.length) lines.push(`  exempt_ips: [${g.exempt_ips.join(', ')}]`);
  }
  return lines.join('\n') + '\n';
}

// Errors are codes (editor.yamlErr.<code> in the locales) with their
// arguments, so the editor shows them in the user's language.
export type YamlErrorCode =
  | 'tab' | 'indent' | 'keyValue' | 'twice' | 'mode' | 'oversize' | 'responseNext'
  | 'bool' | 'list' | 'guard' | 'guardTwice' | 'unknown' | 'modeRequired' | 'canary' | 'canaryMode';

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
      case 'geo_restrictions': {
        const geo: any = {};
        while (i < lines.length && lines[i].indent !== 0) {
          const c = lines[i];
          if (c.indent < 0) return fail(c.n, 'tab');
          const cm = /^([a-z_]+):(.*)$/.exec(c.text);
          if (!cm) return fail(c.n, 'keyValue');
          const [, ck, cv] = cm;
          i++;
          if (ck === 'default_action') {
            geo.default_action = scalar(cv);
          } else if (ck === 'enabled') {
            const b = bool(cv, c.n);
            if (isErr(b)) return { error: b };
            geo.enabled = b;
          } else if (['blocked_countries', 'challenged_countries', 'exempt_ips'].includes(ck)) {
            const list = flowList(cv, c.n);
            if (isErr(list)) return { error: list };
            geo[ck] = list;
          } else if (['blocked_asns', 'challenged_asns'].includes(ck)) {
            const list = flowList(cv, c.n);
            if (isErr(list)) return { error: list };
            geo[ck] = list.map((x) => Number(x)).filter((n) => !isNaN(n) && n > 0);
          }
        }
        (spec as any).geo_restrictions = geo;
        break;
      }
      default:
        return fail(l.n, 'unknown', { key });
    }
  }
  if (!spec.mode) return fail(1, 'modeRequired');
  if (canaryLine && spec.mode !== 'MODE_ENFORCE') return fail(canaryLine, 'canaryMode');
  return { spec };
}

// normalized: the spec the API stores for the same content (what the form
// shows, what is sent on save).
export function normalizeSpec(spec: PolicySpec): PolicySpec {
  const out: PolicySpec = { mode: spec.mode && spec.mode !== 'MODE_UNSPECIFIED' ? spec.mode : 'MODE_SHADOW' };
  if (spec.oversize && spec.oversize !== 'OVERSIZE_UNSPECIFIED') out.oversize = spec.oversize;
  // a canary only exists on an enforce policy
  if (out.mode === 'MODE_ENFORCE' && validCanary(spec.canary_percent)) out.canary_percent = spec.canary_percent;
  const r = spec.response;
  const guards = (r?.data_guard ?? []).filter((g) => (DATA_GUARDS as readonly string[]).includes(g));
  if (r && (r.allowed_codes_check || r.db_errors || guards.length)) {
    out.response = {};
    if (r.allowed_codes_check) out.response.allowed_codes_check = true;
    if (r.db_errors) out.response.db_errors = true;
    if (guards.length) out.response.data_guard = guards;
  }
  if ((spec as any).geo_restrictions) {
    (out as any).geo_restrictions = (spec as any).geo_restrictions;
  }
  return out;
}
