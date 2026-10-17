import React, { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Lock, Copy, Check, ChevronDown, ChevronRight, AlertTriangle } from 'lucide-react';
import { Event, GetEventResponse } from '../../api/client';
import { useAuth } from '../../context/AuthContext';
import { fieldLocation, markPath } from '../../lib/trace';
import { SectionTitle, formatTime, relativeTime, verdictOf } from '../ui';
import { href } from '../../router';

type Rules = GetEventResponse['rules'];

export const CopyButton: React.FC<{ text: string; label: string; testId?: string }> = ({ text, label, testId }) => {
  const { t } = useTranslation();
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      data-testid={testId}
      onClick={() => {
        void navigator.clipboard?.writeText(text).then(() => {
          setDone(true);
          setTimeout(() => setDone(false), 1500);
        });
      }}
      className="inline-flex h-7 items-center gap-1 rounded px-2 text-xs text-muted hover:bg-sunken hover:text-ink"
      aria-label={label}
    >
      {done ? <Check className="w-3.5 h-3.5 text-ok" /> : <Copy className="w-3.5 h-3.5" />}
      {done ? t('common.copied') : label}
    </button>
  );
};

const severityClass: Record<string, string> = {
  critical: 'text-block border-block/40',
  high: 'text-block border-block/30',
  error: 'text-block border-block/30',
  medium: 'text-shadow border-shadow/40',
  warning: 'text-shadow border-shadow/40',
  low: 'text-muted border-line',
  notice: 'text-muted border-line',
};

const ScoreBar: React.FC<{ label: string; value: number; max: number; strong?: boolean }> = ({ label, value, max, strong }) => (
  <div className="grid grid-cols-[8rem_1fr_3rem] items-center gap-3 text-[13px]">
    <span className={strong ? 'font-semibold text-ink' : 'text-muted'}>{label}</span>
    <div className="h-2 rounded-full bg-sunken overflow-hidden border border-line/40" aria-hidden>
      <div
        className={`h-full rounded-full transition-all ${
          strong
            ? 'bg-gradient-to-r from-cyan-500 to-sky-400 shadow-[0_0_8px_rgba(6,182,212,0.8)]'
            : value > 0
            ? 'bg-gradient-to-r from-rose-500 to-rose-400 shadow-[0_0_8px_rgba(244,63,94,0.6)]'
            : 'bg-transparent'
        }`}
        style={{ width: `${max > 0 ? Math.min(100, (value / max) * 100) : 0}%` }}
      />
    </div>
    <span className={`text-right tabular-nums font-mono ${strong ? 'font-bold text-cyan-400' : 'text-muted'}`}>{value}</span>
  </div>
);

const Detail: React.FC<{ label: string; children: React.ReactNode; testId?: string }> = ({ label, children, testId }) => (
  <div className="grid grid-cols-[7.5rem_1fr] gap-3 py-2 border-b border-line last:border-0 text-[13px]">
    <dt className="text-muted">{label}</dt>
    <dd className="min-w-0 break-words" data-testid={testId}>
      {children}
    </dd>
  </div>
);

/** The request path with the violating part marked. */
export const MarkedPath: React.FC<{ event: Event }> = ({ event }) => (
  <>
    {markPath(event.http_path ?? '', (event.violations ?? []).map((v) => v.field ?? '')).map((seg, i) =>
      seg.mark ? (
        <mark key={i} data-testid="path-highlight" className="rounded-sm bg-shadow/25 px-0.5 text-ink">
          {seg.text}
        </mark>
      ) : (
        <React.Fragment key={i}>{seg.text}</React.Fragment>
      ),
    )}
  </>
);

// The decision trace of one event: why the verdict, what matched where,
// and the request it was taken on. Viewers get the client IP and the
// input snippets masked (by the API, and again here).
export const EventTrace: React.FC<{ event: Event; rules?: Rules }> = ({ event, rules }) => {
  const { t, i18n } = useTranslation();
  const { isViewer, maskIp, maskSnippet } = useAuth();
  const [raw, setRaw] = useState(false);
  const locale = i18n.language;
  const violations = event.violations ?? [];
  const extraRules = (event.matched_rules ?? []).filter((id) => !violations.some((v) => v.rule_id === id));
  const scoreMax = Math.max(event.score_anomaly ?? 0, event.score_protocol ?? 0, event.score_sqli ?? 0, event.score_xss ?? 0, 1);
  const verdict = verdictOf(event.action);
  const ruleCount = new Set([...(event.matched_rules ?? []), ...violations.map((v) => v.rule_id)]).size;
  const ip = maskIp(event.client_ip);

  return (
    <div className="grid gap-5 lg:grid-cols-[minmax(0,1fr)_22rem]" data-testid="event-detail">
      <div className="min-w-0 space-y-5">
        {isViewer && (
          <div data-testid="viewer-notice" className="flex items-start gap-2.5 rounded-md border border-shadow/40 bg-shadow/10 px-3 py-2.5 text-[13px]">
            <Lock className="mt-0.5 w-4 h-4 shrink-0 text-shadow" />
            <span>{t('detail.viewerNotice')}</span>
          </div>
        )}

        {event.inspection && event.inspection !== 'full' && (
          <div data-testid="truncation-notice" className="flex items-start gap-2.5 rounded-md border border-shadow/40 bg-shadow/10 px-3 py-2.5 text-[13px]">
            <AlertTriangle className="mt-0.5 w-4 h-4 shrink-0 text-shadow" />
            <span>
              {event.inspection === 'partial'
                ? t('detail.inspection.partial', 'Not fully inspected: the CPU budget ran out and the fail mode applied. Rules after that point did not run.')
                : t('detail.inspection.body_skipped', 'The request body, or part of it, was not inspected (over the inspection limit or spooled to disk).')}
            </span>
          </div>
        )}

        <section className="panel">
          <SectionTitle>{t('detail.verdictTitle')}</SectionTitle>
          <div className="px-5 py-4 space-y-4">
            <div
              className={`p-4 rounded-xl border ${
                verdict === 'block'
                  ? 'border-rose-500/40 bg-rose-500/10 text-rose-200 shadow-[0_0_16px_rgba(244,63,94,0.1)]'
                  : verdict === 'shadow'
                  ? 'border-amber-500/40 bg-amber-500/10 text-amber-200 shadow-[0_0_16px_rgba(245,158,11,0.1)]'
                  : 'border-line bg-sunken/40 text-ink'
              }`}
            >
              <p className="text-[14px] leading-relaxed font-semibold max-w-[72ch]" data-testid="verdict-summary">
                {t(`detail.summary.${verdict}`, {
                  policy: event.policy_id || '—',
                  version: event.policy_version ?? 0,
                  score: event.score_anomaly ?? 0,
                  count: ruleCount,
                })}
              </p>
            </div>
            <div className="space-y-2.5 pt-1">
              <ScoreBar label={t('detail.scoreProtocol')} value={event.score_protocol ?? 0} max={scoreMax} />
              <ScoreBar label={t('detail.scoreSqli')} value={event.score_sqli ?? 0} max={scoreMax} />
              <ScoreBar label={t('detail.scoreXss')} value={event.score_xss ?? 0} max={scoreMax} />
              <ScoreBar label={t('detail.scoreAnomaly')} value={event.score_anomaly ?? 0} max={scoreMax} strong />
            </div>
          </div>
        </section>

        <section className="panel">
          <SectionTitle>{t('detail.requestTitle')}</SectionTitle>
          <div className="px-5 py-4">
            <div className="font-mono text-[13px] leading-relaxed break-all rounded-lg border border-line bg-sunken/60 p-3 shadow-xs" data-testid="request-line">
              <span className="font-semibold text-accent">{event.http_method}</span> <span className="text-muted">{event.http_host}</span>
              <MarkedPath event={event} />
              {event.status_code ? <span className="ml-2 px-1.5 py-0.5 rounded text-xs font-semibold bg-surface border border-line text-muted">→ {event.status_code}</span> : null}
            </div>
            {(event.inspection === 'partial' || event.inspection === 'body_skipped') && (
              <p data-testid="inspection-warning" className="mt-3 rounded-lg border border-shadow/40 bg-shadow/10 px-3.5 py-2.5 text-[13px]">
                {t(`detail.inspection.${event.inspection}`)}
              </p>
            )}
            {(event.user_agent || event.referer) && (
              <dl className="mt-3">
                {event.user_agent && (
                  <Detail label="User-Agent" testId="detail-user-agent">
                    <span className="font-mono text-xs break-all">{event.user_agent}</span>
                  </Detail>
                )}
                {event.referer && (
                  <Detail label="Referer" testId="detail-referer">
                    <span className="font-mono text-xs break-all">{event.referer}</span>
                  </Detail>
                )}
              </dl>
            )}
            {(event.headers?.length ?? 0) > 0 && (
              <details className="mt-3" data-testid="detail-headers">
                <summary className="cursor-pointer text-[13px] text-muted hover:text-ink">
                  {t('detail.headers', { count: event.headers?.length ?? 0 })}
                </summary>
                <table className="mt-2 w-full text-xs">
                  <tbody>
                    {event.headers?.map((h, i) => (
                      <tr key={i} className="border-b border-line last:border-0" data-testid="header-row">
                        <td className="py-1.5 pr-3 align-top font-mono text-muted whitespace-nowrap">{h.name}</td>
                        <td className={`py-1.5 font-mono break-all ${h.value === '[MASKED]' || h.value === '[REDACTED]' ? 'text-faint italic' : ''}`}>
                          {h.value}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </details>
            )}
          </div>
        </section>

        <section className="panel">
          <SectionTitle aside={t('detail.violationCount', { count: violations.length })}>{t('detail.violationsTitle')}</SectionTitle>
          {violations.length === 0 ? (
            <p className="px-4 py-6 text-center text-[13px] text-muted">{t('detail.noViolations')}</p>
          ) : (
            <ol className="divide-y divide-line">
              {violations.map((v, idx) => {
                const rule = rules?.[String(v.rule_id)];
                const loc = fieldLocation(v.field ?? '');
                return (
                  <li key={idx} className="px-4 py-4" data-testid="violation-item">
                    <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
                      <a href={href({ page: 'events', query: { rule_id: String(v.rule_id) } })} className="font-mono font-medium text-accent hover:underline" title={t('detail.eventsWithRule')}>
                        {t('detail.rule', { id: v.rule_id })}
                      </a>
                      {rule?.severity && (
                        <span className={`rounded border px-1.5 text-[11px] ${severityClass[rule.severity.toLowerCase()] ?? 'text-muted border-line'}`}>{rule.severity}</span>
                      )}
                      {v.layer && <span className="text-xs text-muted">{t('detail.layerName', { layer: v.layer })}</span>}
                    </div>
                    {rule && (
                      <div data-testid="rule-meta" className="mt-1 text-[13px]">
                        <span className="font-medium">{rule.name}</span>
                        {rule.source && <span className="ml-2 text-xs text-muted">{t('detail.ruleSource')}: {rule.source}</span>}
                        {rule.source === 'sigma' && rule.author && (
                          <div data-testid="rule-author" className="text-xs text-muted">
                            {t('detail.ruleAuthor')}: {rule.author}
                            {rule.license && <span className="text-faint"> ({rule.license})</span>}
                          </div>
                        )}
                      </div>
                    )}
                    <div className="mt-3 grid gap-2 sm:grid-cols-[9rem_1fr] text-[13px]">
                      <span className="text-muted">{t('detail.field')}</span>
                      <span>
                        <mark data-testid="field-highlight" className="rounded-sm bg-shadow/25 px-1 font-mono text-ink">
                          {v.field}
                        </mark>
                        <span className="ml-2 text-xs text-muted">{t(`detail.where.${loc.kind}`)}</span>
                      </span>
                      <span className="text-muted">{t('detail.snippet')}</span>
                      <pre data-testid="violation-snippet" className="rounded border border-line bg-sunken/60 px-2.5 py-1.5 font-mono text-xs whitespace-pre-wrap break-all">
                        {maskSnippet(v.snippet)}
                      </pre>
                    </div>
                  </li>
                );
              })}
            </ol>
          )}
          {extraRules.length > 0 && (
            <p className="border-t border-line px-4 py-3 text-xs text-muted" data-testid="extra-rules">
              {t('detail.alsoMatched')}{' '}
              {extraRules.map((id, i) => (
                <React.Fragment key={id}>
                  {i > 0 && ', '}
                  <a className="font-mono text-accent hover:underline" href={href({ page: 'events', query: { rule_id: String(id) } })}>
                    {id}
                  </a>
                  {rules?.[String(id)] && <span> {rules[String(id)].name}</span>}
                </React.Fragment>
              ))}
            </p>
          )}
        </section>

        <section className="panel">
          <button type="button" onClick={() => setRaw(!raw)} aria-expanded={raw} data-testid="raw-toggle" className="flex w-full items-center gap-2 px-4 py-3 text-[13px] font-semibold">
            {raw ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
            {t('detail.raw')}
          </button>
          {raw && (
            <div className="border-t border-line">
              <div className="flex justify-end px-2 pt-2">
                <CopyButton text={JSON.stringify(event, null, 2)} label={t('detail.copyJson')} />
              </div>
              <pre data-testid="raw-json" className="max-h-[28rem] overflow-auto px-4 pb-4 font-mono text-xs">
                {JSON.stringify({ ...event, client_ip: ip, violations: violations.map((v) => ({ ...v, snippet: maskSnippet(v.snippet) })) }, null, 2)}
              </pre>
            </div>
          )}
        </section>
      </div>

      <aside className="space-y-5 min-w-0">
        <section className="panel">
          <SectionTitle>{t('detail.requestInfo')}</SectionTitle>
          <dl className="px-4 py-1">
            <Detail label={t('detail.timestamp')}>
              <div>{formatTime(event.timestamp, locale, '—')}</div>
              <div className="text-xs text-muted">{relativeTime(event.timestamp, locale)}</div>
            </Detail>
            <Detail label={t('detail.clientIp')} testId="detail-client-ip">
              <span className="font-mono">{ip}</span>
            </Detail>
            {event.identity && <Detail label={t('detail.identity')}>{event.identity}</Detail>}
            <Detail label={t('detail.policy')}>
              {event.policy_id ? (
                <a className="text-accent hover:underline" href={href({ page: 'events', query: { policy_id: event.policy_id } })}>
                  {event.policy_id}
                </a>
              ) : (
                '—'
              )}
              <span className="ml-1 text-muted">v{event.policy_version}</span>
            </Detail>
            <Detail label={t('detail.nodeId')}>
              <span className="font-mono text-xs">{event.node_id}</span>
              {event.connector_type && <div className="text-xs text-muted">{event.connector_type}</div>}
            </Detail>
            <Detail label={t('detail.statusCode')}>{event.status_code || '—'}</Detail>
            <Detail label={t('detail.requestId')}>
              <span className="font-mono text-xs">{event.request_id || '—'}</span>
            </Detail>
            {event.received_at && (
              <Detail label={t('detail.received')}>
                <span className="text-muted">{formatTime(event.received_at, locale, '—')}</span>
              </Detail>
            )}
          </dl>
        </section>

        <section className="panel">
          <SectionTitle>{t('detail.investigate')}</SectionTitle>
          <ul className="px-4 py-2 text-[13px]">
            {!isViewer && event.client_ip && (
              <li className="py-1.5">
                <a data-testid="link-same-ip" className="text-accent hover:underline" href={href({ page: 'events', query: { client_ip: event.client_ip, range: '7d' } })}>
                  {t('detail.sameIp')}
                </a>
              </li>
            )}
            {event.matched_rules?.[0] !== undefined && (
              <li className="py-1.5">
                <a data-testid="link-same-rule" className="text-accent hover:underline" href={href({ page: 'events', query: { rule_id: String(event.matched_rules[0]), range: '24h' } })}>
                  {t('detail.sameRule', { id: event.matched_rules[0] })}
                </a>
              </li>
            )}
            {event.policy_id && (
              <li className="py-1.5">
                <a className="text-accent hover:underline" href={href({ page: 'overview', query: { policy_id: event.policy_id, range: '24h' } })}>
                  {t('detail.policyOverview')}
                </a>
              </li>
            )}
          </ul>
        </section>
      </aside>
    </div>
  );
};

