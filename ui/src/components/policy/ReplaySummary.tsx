import React from 'react';
import { useTranslation } from 'react-i18next';
import type { Operation, ReplayComparison, ReplayReport } from '../../api/client';
import { useAuth } from '../../context/AuthContext';

const maximum = 18446744073709551615n;
export function replayCount(value?: string): bigint | undefined {
  if (value === undefined) return 0n; // proto JSON omits zero values
  if (!/^(0|[1-9][0-9]{0,19})$/.test(value)) return undefined;
  const n = BigInt(value);
  return n <= maximum ? n : undefined;
}
const hash = (value?: string) => !!value && /^[a-f0-9]{64}$/.test(value);
export function reviewableReplay(op?: Operation): op is Operation & { id: string; replay: ReplayReport } {
  if (!op?.id || op.state !== 'DONE' || op.done !== true || !op.replay) return false;
  const r = op.replay, samples = replayCount(r.samples);
  const comparisons = [r.traffic, r.corpus];
  const valid = comparisons.every(c => !c || (
    ['samples', 'newly_blocked', 'newly_allowed'].every(k => replayCount(c[k as 'samples']) !== undefined) &&
    [c.draft_actions, c.baseline_actions, c.newly_blocked_rules, c.newly_allowed_rules, c.newly_blocked_paths, c.newly_blocked_sampled, c.newly_allowed_sampled]
      .every(m => !m || Object.values(m).every(n => replayCount(n) !== undefined)) &&
    (replayCount(c.newly_blocked) ?? 0n) <= (replayCount(c.samples) ?? 0n) &&
    (replayCount(c.newly_allowed) ?? 0n) <= (replayCount(c.samples) ?? 0n)));
  const total = comparisons.reduce((n, c) => n + (replayCount(c?.samples) ?? 0n), 0n);
  return valid && samples === total && samples !== undefined && samples > 0n && hash(r.input_digest) && hash(r.draft_sha256) && hash(r.baseline_sha256) && hash(r.replay_sha256);
}

export const ReplaySummary: React.FC<{ operation?: Operation; unavailable?: boolean }> = ({ operation: op, unavailable }) => {
  const { t } = useTranslation();
  const { isViewer } = useAuth();
  if (unavailable) return <p role="alert">{t('replay.unavailable')}</p>;
  if (!op) return <p>{t('replay.missing')}</p>;
  const count = (value?: string) => replayCount(value)?.toString() ?? t('replay.invalidCount');
  const map = (label: string, values?: Record<string, string>) => {
    const entries = Object.entries(values ?? {}).sort((a, b) => {
      const x = replayCount(a[1]) ?? -1n, y = replayCount(b[1]) ?? -1n;
      return x === y ? a[0].localeCompare(b[0]) : x > y ? -1 : 1;
    });
    return entries.length > 0 && <div><h4 className="font-medium mt-3">{t(`replay.${label}`)}</h4>
      <ul>{entries.slice(0, 10).map(([key, value]) => <li key={key} className="break-all"><code>{key}</code>: {count(value)}</li>)}</ul>
      {entries.length > 10 && <p className="text-muted">{t('replay.topTen')}</p>}</div>;
  };
  const comparison = (label: string, value?: ReplayComparison) => <section className="panel p-3 min-w-0" key={label}>
    <h3 className="font-semibold">{t(`replay.${label}`)}</h3>
    {!value ? <p>{t('replay.noSamples')}</p> : <>
      <dl className="grid grid-cols-2 gap-2 mt-2">
        {(['samples', 'newly_blocked', 'newly_allowed'] as const).map(key => <React.Fragment key={key}><dt>{t(`replay.${key}`)}</dt><dd className="font-mono break-all">{count(value[key])}</dd></React.Fragment>)}
      </dl>
      {map('draftActions', value.draft_actions)}{map('baselineActions', value.baseline_actions)}
      {map('blockedRules', value.newly_blocked_rules)}{map('allowedRules', value.newly_allowed_rules)}
      {map('blockedPaths', value.newly_blocked_paths)}
      {map('blockedSampled', value.newly_blocked_sampled)}{map('allowedSampled', value.newly_allowed_sampled)}
      {!isViewer && (['examples_blocked', 'examples_allowed'] as const).map(key => (value[key]?.length ?? 0) > 0 && <details key={key} className="mt-3">
        <summary>{t(`replay.${key}`)}</summary>
        <ul>{value[key]?.slice(0, 5).map((example, i) => <li key={i} className="font-mono text-xs break-all py-1">
          {example.method} {example.raw_uri}<br />{example.baseline} → {example.draft}<br />
          {t('replay.rules')}: {example.baseline_rules?.join(', ') || '—'} → {example.draft_rules?.join(', ') || '—'}
        </li>)}</ul>
      </details>)}
    </>}
  </section>;
  return <section data-testid="replay-summary" className="text-[13px] space-y-3 min-w-0">
    <p className="break-all"><strong>{t('replay.title')}</strong> · {op.id} · {t(`replay.state.${op.state}`)}</p>
    {op.state === 'FAILED' && <p role="alert">{t('replay.failed')}</p>}
    {(op.state === 'PENDING' || op.state === 'RUNNING') && <p role="status">{t('replay.waiting')}</p>}
    {op.state === 'DONE' && op.replay && <>
      {!reviewableReplay(op) && <p role="alert">{t('replay.incomplete')}</p>}
      <p>{t('replay.total', { samples: count(op.replay.samples), ms: count(op.replay.elapsed_ms) })}</p>
      <p>{t('replay.baseline', { bundle: count(op.replay.baseline_bundle) })}</p>
      {op.replay.truncated && <p role="alert">{t('replay.truncated')}</p>}
      <p className="text-muted">{t('replay.candidates')}</p>
      {/* RS-5: what the draft changes in the rules' actions, whatever the traffic */}
      {op.replay.rule_actions && <section className="panel p-3 min-w-0" data-testid="replay-rule-actions">
        <h3 className="font-semibold">{t('replay.ruleActions', { count: op.replay.rule_actions.changed ?? 0 })}</h3>
        {(op.replay.rule_actions.rules?.length ?? 0) > 0 && <ul className="mt-2 max-h-64 overflow-y-auto">
          {op.replay.rule_actions.rules?.map((c) => <li key={c.rule} className="flex flex-wrap gap-x-2 py-0.5">
            <code>{c.rule}</code><span className="min-w-0 flex-1 truncate" title={c.name}>{c.name}</span>
            <span>{t(`editor.ruleSets.effective.${c.from}`)} → <strong className={c.to === 'block' ? 'text-block' : undefined}>{t(`editor.ruleSets.effective.${c.to}`)}</strong></span>
            <span className="text-muted">{c.source === 'set' ? c.set : t(`editor.ruleSets.source.${c.source}`)}</span>
          </li>)}
        </ul>}
        {(op.replay.rule_actions.changed ?? 0) > (op.replay.rule_actions.rules?.length ?? 0) && <p className="text-muted">{t('replay.ruleActionsMore', { shown: op.replay.rule_actions.rules?.length ?? 0 })}</p>}
      </section>}
      <div className="grid gap-3 md:grid-cols-2">{comparison('traffic', op.replay.traffic)}{comparison('corpus', op.replay.corpus)}</div>
      <details><summary>{t('replay.provenance')}</summary><dl className="space-y-2">
        {(['input_digest', 'draft_sha256', 'baseline_sha256', 'replay_sha256'] as const).map(key => <div key={key}><dt>{t(`replay.${key}`)}</dt><dd className="font-mono text-xs break-all">{op.replay?.[key] || '—'}</dd></div>)}
      </dl></details>
    </>}
  </section>;
};
