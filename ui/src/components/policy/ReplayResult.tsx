import React from 'react';
import { useTranslation } from 'react-i18next';
import type { Operation, ReplayComparison, ReplayExample } from '../../api/client';
import { formatCount } from '../ui';

// 64-bit counters come as strings (protobuf JSON)
const n = (v: string | number | undefined): number => Number(v ?? 0);

const top = (m: Record<string, string | number> | undefined, k = 5): [string, number][] =>
  Object.entries(m ?? {})
    .map(([key, v]) => [key, n(v)] as [string, number])
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, k);

const stateClass: Record<string, string> = {
  DONE: 'text-ok border-ok/30 bg-ok/10',
  FAILED: 'text-block border-block/30 bg-block/10',
  RUNNING: 'text-shadow border-shadow/35 bg-shadow/10',
  PENDING: 'text-muted border-line',
};

export const ReplayState: React.FC<{ op?: Operation }> = ({ op }) => {
  const { t } = useTranslation();
  const state = op?.state ?? 'NONE';
  return (
    <span
      data-testid="replay-state"
      data-state={state}
      className={`inline-block rounded border px-1.5 py-0.5 text-xs font-medium ${stateClass[state] ?? 'text-muted border-line'}`}
    >
      {t(`replay.state.${state}`, { defaultValue: state })}
    </span>
  );
};

const Examples: React.FC<{ title: string; rows?: ReplayExample[]; testId: string }> = ({ title, rows, testId }) => {
  if (!rows?.length) return null;
  return (
    <div className="mt-2" data-testid={testId}>
      <div className="label mb-1">{title}</div>
      <ul className="space-y-1 text-xs">
        {rows.map((e, i) => (
          <li key={i} className="font-mono break-all">
            <span className="text-muted">{e.method}</span> {e.raw_uri}{' '}
            <span className="text-muted">
              {e.baseline} → {e.draft} ({(e.draft_rules?.length ? e.draft_rules : e.baseline_rules ?? []).join(', ')})
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
};

// One comparison: the draft against the bundle in force, on the traffic
// samples or on the corpus.
const Comparison: React.FC<{ kind: 'traffic' | 'corpus'; c?: ReplayComparison }> = ({ kind, c }) => {
  const { t, i18n } = useTranslation();
  if (!c) {
    return (
      <div className="rounded border border-line p-3 text-[13px] text-muted" data-testid={`replay-${kind}`} data-empty="true">
        <div className="font-medium text-ink">{t(`replay.${kind}`)}</div>
        {t(`replay.none.${kind}`)}
      </div>
    );
  }
  const blocked = n(c.newly_blocked);
  const allowed = n(c.newly_allowed);
  const fmt = (x: number) => formatCount(x, i18n.language);
  return (
    <div className="rounded border border-line p-3 text-[13px]" data-testid={`replay-${kind}`}>
      <div className="flex items-baseline justify-between">
        <span className="font-medium">{t(`replay.${kind}`)}</span>
        <span className="text-xs text-muted">{t('replay.samples', { count: n(c.samples), n: fmt(n(c.samples)) })}</span>
      </div>
      <dl className="mt-2 grid grid-cols-2 gap-2">
        <div>
          <dt className="label">{t(`replay.newlyBlocked.${kind}`)}</dt>
          <dd className={`text-lg tabular-nums ${blocked > 0 && kind === 'traffic' ? 'text-block' : ''}`} data-testid={`replay-${kind}-blocked`}>
            {fmt(blocked)}
          </dd>
        </div>
        <div>
          <dt className="label">{t(`replay.newlyAllowed.${kind}`)}</dt>
          <dd className={`text-lg tabular-nums ${allowed > 0 ? 'text-block' : ''}`} data-testid={`replay-${kind}-allowed`}>
            {fmt(allowed)}
          </dd>
        </div>
      </dl>
      {blocked > 0 && (
        <div className="mt-2 grid gap-2 sm:grid-cols-2">
          <div>
            <div className="label mb-1">{t('replay.rules')}</div>
            <ul className="text-xs tabular-nums" data-testid={`replay-${kind}-rules`}>
              {top(c.newly_blocked_rules).map(([id, k]) => (
                <li key={id}>
                  {id} <span className="text-muted">× {fmt(k)}</span>
                </li>
              ))}
            </ul>
          </div>
          <div>
            <div className="label mb-1">{t('replay.paths')}</div>
            <ul className="text-xs" data-testid={`replay-${kind}-paths`}>
              {top(c.newly_blocked_paths).map(([p, k]) => (
                <li key={p} className="font-mono">
                  {p} <span className="text-muted">× {fmt(k)}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}
      <Examples title={t('replay.examplesBlocked')} rows={c.examples_blocked} testId={`replay-${kind}-examples`} />
      <Examples title={t('replay.examplesAllowed')} rows={c.examples_allowed} testId={`replay-${kind}-examples-allowed`} />
    </div>
  );
};

// The replay of a draft (W13-G2-01): candidate false positives (newly
// blocked) and false negatives (newly allowed) against the bundle in force,
// on the policy's traffic samples and on the corpus apart.
export const ReplayResult: React.FC<{ op?: Operation }> = ({ op }) => {
  const { t } = useTranslation();
  if (!op) return <p className="text-[13px] text-muted" data-testid="replay-missing">{t('replay.missing')}</p>;
  if (op.state === 'FAILED') {
    return (
      <p className="text-[13px] text-block" data-testid="replay-error">
        {t('replay.failed', { error: op.error })}
      </p>
    );
  }
  if (!op.done || !op.replay) return <p className="text-[13px] text-muted" data-testid="replay-running">{t('replay.running')}</p>;
  const r = op.replay;
  return (
    <div data-testid="replay-result">
      <p className="mb-2 text-xs text-muted">
        {n(r.baseline_bundle) > 0 ? t('replay.against', { bundle: n(r.baseline_bundle) }) : t('replay.againstNone')}
        {r.truncated ? ` ${t('replay.truncated')}` : ''}
      </p>
      <div className="grid gap-3 lg:grid-cols-2">
        <Comparison kind="traffic" c={r.traffic} />
        <Comparison kind="corpus" c={r.corpus} />
      </div>
    </div>
  );
};
