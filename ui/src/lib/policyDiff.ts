// Diff of two policy versions, block by block (W12-F-01). The blocks are
// those of docs/spec/policies.schema.json: the general block (mode,
// oversize) and the response layer. Values are shown as the YAML of the
// editor writes them (shadow, block, true...), after normalizeSpec, so a
// field the API leaves out and its default compare equal.
import { DATA_GUARDS, PolicySpec, advancedSpec, normalizeSpec } from './policyYaml';

export type DiffBlock = 'general' | 'response' | 'advanced';

export interface FieldDiff {
  key: 'mode' | 'oversize' | 'canary_percent' | 'allowed_codes_check' | 'db_errors' | 'data_guard' | 'advanced';
  from: string;
  to: string;
  changed: boolean;
  // data_guard only: items in "to" and not in "from", and the reverse
  added?: string[];
  removed?: string[];
}

export interface BlockDiff {
  block: DiffBlock;
  fields: FieldDiff[];
  changed: number;
}

const modeOut: Record<string, string> = { MODE_SHADOW: 'shadow', MODE_ENFORCE: 'enforce' };
const oversizeOut: Record<string, string> = { OVERSIZE_PASS: 'pass', OVERSIZE_BLOCK: 'block' };

function field(key: FieldDiff['key'], from: string, to: string): FieldDiff {
  return { key, from, to, changed: from !== to };
}

// diffSpecs compares from with to; every field is listed, changed or not.
export function diffSpecs(fromSpec: PolicySpec, toSpec: PolicySpec): BlockDiff[] {
  const a = normalizeSpec(fromSpec);
  const b = normalizeSpec(toSpec);
  const general = [
    field('mode', modeOut[a.mode ?? ''] ?? 'shadow', modeOut[b.mode ?? ''] ?? 'shadow'),
    field('oversize', oversizeOut[a.oversize ?? ''] ?? 'pass', oversizeOut[b.oversize ?? ''] ?? 'pass'),
    // no canary: every client (an enforce policy blocks for all)
    field('canary_percent', a.canary_percent ? String(a.canary_percent) : '—', b.canary_percent ? String(b.canary_percent) : '—'),
  ];
  // data_guard is a set: order does not count
  const order = (l: string[]) => DATA_GUARDS.filter((g) => l.includes(g));
  const ga = order(a.response?.data_guard ?? []);
  const gb = order(b.response?.data_guard ?? []);
  const guards = field('data_guard', `[${ga.join(', ')}]`, `[${gb.join(', ')}]`);
  guards.added = gb.filter((g) => !ga.includes(g));
  guards.removed = ga.filter((g) => !gb.includes(g));
  const response = [
    field('allowed_codes_check', String(!!a.response?.allowed_codes_check), String(!!b.response?.allowed_codes_check)),
    field('db_errors', String(!!a.response?.db_errors), String(!!b.response?.db_errors)),
    guards,
  ];
  const blocks: BlockDiff[] = [
    { block: 'general', fields: general, changed: general.filter((f) => f.changed).length },
    { block: 'response', fields: response, changed: response.filter((f) => f.changed).length },
  ];
  const from = stable(advancedSpec(a));
  const to = stable(advancedSpec(b));
  if (from !== '{}' || to !== '{}') {
    const entry = field('advanced', from, to);
    blocks.push({ block: 'advanced', fields: [entry], changed: Number(entry.changed) });
  }
  return blocks;
}

function stable(value: unknown): string {
  const sort = (v: unknown): unknown => {
    if (Array.isArray(v)) return v.map(sort);
    if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).sort(([a], [b]) => a.localeCompare(b)).map(([key, val]) => [key, sort(val)]));
    return v;
  };
  return JSON.stringify(sort(value), null, 2);
}
