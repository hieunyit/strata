import React from 'react';
import { useTranslation } from 'react-i18next';
import {
  X,
  ShieldAlert,
  ShieldCheck,
  Eye,
  Lock,
} from 'lucide-react';
import { Event, GetEventResponse } from '../../api/client';
import { useAuth } from '../../context/AuthContext';
import { fieldLocation, markPath } from '../../lib/trace';

interface DecisionTraceModalProps {
  event: Event | null;
  /** the rule catalog's entries for the event's rules (GET /v1/events/{id}) */
  rules?: GetEventResponse['rules'];
  isOpen: boolean;
  onClose: () => void;
  isLoading?: boolean;
}

export const DecisionTraceModal: React.FC<DecisionTraceModalProps> = ({
  event,
  rules,
  isOpen,
  onClose,
  isLoading = false,
}) => {
  const { t } = useTranslation();
  const { isViewer, maskIp, maskSnippet } = useAuth();

  if (!isOpen) return null;


  const getActionBadge = (action: string) => {
    switch (action.toLowerCase()) {
      case 'block':
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-rose-100 text-rose-800 dark:bg-rose-950/60 dark:text-rose-300 border border-rose-200 dark:border-rose-900">
            <ShieldAlert className="w-3.5 h-3.5" />
            {t('events.actions.block')}
          </span>
        );
      case 'shadow':
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-amber-100 text-amber-800 dark:bg-amber-950/60 dark:text-amber-300 border border-amber-200 dark:border-amber-900">
            <Eye className="w-3.5 h-3.5" />
            {t('events.actions.shadow')}
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-emerald-100 text-emerald-800 dark:bg-emerald-950/60 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-900">
            <ShieldCheck className="w-3.5 h-3.5" />
            {t('events.actions.allow')}
          </span>
        );
    }
  };

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto bg-slate-900/60 backdrop-blur-sm flex items-center justify-center p-4">
      <div
        className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl max-w-4xl w-full shadow-2xl overflow-hidden transition-all my-8 animate-in fade-in zoom-in-95 duration-200"
        role="dialog"
        aria-modal="true"
        data-testid="decision-trace-modal"
      >
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-100 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-800/40">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-sky-100 dark:bg-sky-950 text-sky-600 dark:text-sky-300">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-slate-900 dark:text-white flex items-center gap-2">
                <span>{t('detail.title')}</span>
                {event && getActionBadge(event.action)}
              </h2>
              <div className="text-xs text-slate-500 font-mono mt-0.5">
                {event?.block_id}
              </div>
            </div>
          </div>
          <button
            onClick={onClose}
            data-testid="close-modal-btn"
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content Body */}
        <div className="p-6 space-y-6 max-h-[75vh] overflow-y-auto">
          {isLoading && (
            <div className="py-12 text-center text-slate-500">
              {t('events.table.loading')}
            </div>
          )}

          {!isLoading && !event && (
            <div className="py-12 text-center text-slate-500">
              {t('events.table.empty')}
            </div>
          )}

          {!isLoading && event && (
            <>
              {/* Viewer notice banner */}
              {isViewer && (
                <div
                  data-testid="viewer-notice"
                  className="flex items-center gap-2.5 p-3 rounded-xl bg-amber-50 dark:bg-amber-950/40 border border-amber-200 dark:border-amber-800/50 text-xs text-amber-800 dark:text-amber-200"
                >
                  <Lock className="w-4 h-4 shrink-0 text-amber-600 dark:text-amber-400" />
                  <span>{t('detail.viewerNotice')}</span>
                </div>
              )}


              {/* Detection Scores Breakdown */}
              <div>
                <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-3">
                  {t('detail.scoresTitle')}
                </h3>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                  <div className="p-3 rounded-xl bg-slate-50 dark:bg-slate-800/60 border border-slate-100 dark:border-slate-800">
                    <div className="text-xs text-slate-500">{t('detail.scoreProtocol')}</div>
                    <div className="text-xl font-bold text-slate-900 dark:text-white mt-1">
                      {event.score_protocol ?? 0}
                    </div>
                  </div>
                  <div className="p-3 rounded-xl bg-slate-50 dark:bg-slate-800/60 border border-slate-100 dark:border-slate-800">
                    <div className="text-xs text-slate-500">{t('detail.scoreSqli')}</div>
                    <div className="text-xl font-bold text-rose-600 dark:text-rose-400 mt-1">
                      {event.score_sqli ?? 0}
                    </div>
                  </div>
                  <div className="p-3 rounded-xl bg-slate-50 dark:bg-slate-800/60 border border-slate-100 dark:border-slate-800">
                    <div className="text-xs text-slate-500">{t('detail.scoreXss')}</div>
                    <div className="text-xl font-bold text-amber-600 dark:text-amber-400 mt-1">
                      {event.score_xss ?? 0}
                    </div>
                  </div>
                  <div className="p-3 rounded-xl bg-sky-50 dark:bg-sky-950/40 border border-sky-100 dark:border-sky-900/50">
                    <div className="text-xs text-sky-700 dark:text-sky-300 font-medium">
                      {t('detail.scoreAnomaly')}
                    </div>
                    <div className="text-xl font-bold text-sky-800 dark:text-sky-200 mt-1">
                      {event.score_anomaly ?? 0}
                    </div>
                  </div>
                </div>
              </div>

              {/* Request Metadata Info Card */}
              <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-800/40 border border-slate-200/80 dark:border-slate-800">
                <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-3">
                  {t('detail.requestInfo')}
                </h3>
                <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-y-3 gap-x-6 text-xs">
                  <div>
                    <span className="text-slate-500">{t('detail.method')}:</span>{' '}
                    <span className="font-semibold text-slate-800 dark:text-slate-200 font-mono">
                      {event.http_method}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-500">{t('detail.statusCode')}:</span>{' '}
                    <span className="font-semibold text-slate-800 dark:text-slate-200 font-mono">
                      {event.status_code}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-500">{t('detail.clientIp')}:</span>{' '}
                    <span
                      data-testid="modal-client-ip"
                      className="font-semibold text-slate-800 dark:text-slate-200 font-mono"
                    >
                      {maskIp(event.client_ip)}
                    </span>
                  </div>
                  <div className="sm:col-span-2">
                    <span className="text-slate-500">{t('detail.path')}:</span>{' '}
                    <span className="font-semibold text-slate-800 dark:text-slate-200 font-mono break-all">
                      {event.http_host}
                      {markPath(event.http_path ?? '', (event.violations ?? []).map((v) => v.field ?? '')).map((seg, i) =>
                        seg.mark ? (
                          <mark
                            key={i}
                            data-testid="path-highlight"
                            className="rounded px-0.5 bg-amber-200 text-amber-950 dark:bg-amber-500/40 dark:text-amber-100"
                          >
                            {seg.text}
                          </mark>
                        ) : (
                          <React.Fragment key={i}>{seg.text}</React.Fragment>
                        ),
                      )}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-500">{t('detail.nodeId')}:</span>{' '}
                    <span className="text-slate-700 dark:text-slate-300 font-mono">
                      {event.node_id}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-500">{t('detail.policy')}:</span>{' '}
                    <span className="text-slate-700 dark:text-slate-300 font-mono">
                      {event.policy_id} (v{event.policy_version})
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-500">{t('detail.requestId')}:</span>{' '}
                    <span className="text-slate-700 dark:text-slate-300 font-mono text-[11px] truncate">
                      {event.request_id || '—'}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-500">{t('detail.timestamp')}:</span>{' '}
                    <span className="text-slate-700 dark:text-slate-300">
                      {new Date(event.timestamp).toLocaleString()}
                    </span>
                  </div>
                </div>
              </div>

              {/* Violations List */}
              <div>
                <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-3 flex items-center justify-between">
                  <span>{t('detail.violationsTitle')}</span>
                  <span className="text-slate-400 font-normal normal-case">
                    {event.violations?.length || 0} violations
                  </span>
                </h3>

                {(!event.violations || event.violations.length === 0) ? (
                  <div className="p-4 rounded-xl border border-dashed border-slate-200 dark:border-slate-800 text-center text-xs text-slate-400">
                    {t('detail.noViolations')}
                  </div>
                ) : (
                  <div className="space-y-3">
                    {event.violations.map((violation, idx) => (
                      <div
                        key={idx}
                        className="p-3.5 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 shadow-sm"
                        data-testid="violation-item"
                      >
                        <div className="flex items-center justify-between gap-2 mb-2">
                          <div className="flex items-center gap-2">
                            <span className="px-2 py-0.5 rounded text-xs font-semibold font-mono bg-sky-100 text-sky-800 dark:bg-sky-950 dark:text-sky-300">
                              Rule {violation.rule_id}
                            </span>
                            <span className="px-2 py-0.5 rounded text-xs font-medium bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300 uppercase">
                              {violation.layer}
                            </span>
                          </div>
                          <span className="text-xs font-mono text-slate-500">
                            {t('detail.field')}:{' '}
                            <mark
                              data-testid="field-highlight"
                              className="rounded px-1 py-0.5 font-semibold bg-amber-200 text-amber-950 dark:bg-amber-500/40 dark:text-amber-100"
                            >
                              {violation.field}
                            </mark>{' '}
                            <span className="text-slate-400">({t(`detail.where.${fieldLocation(violation.field ?? '').kind}`)})</span>
                          </span>
                        </div>
                        {(() => {
                          const rule = rules?.[String(violation.rule_id)];
                          if (!rule) return null;
                          return (
                            <div data-testid="rule-meta" className="mb-2 text-xs text-slate-600 dark:text-slate-300">
                              <span className="font-medium">{rule.name}</span>
                              {rule.source && <span className="text-slate-400"> · {t('detail.ruleSource')}: {rule.source}</span>}
                              {rule.source === 'sigma' && rule.author && (
                                <div data-testid="rule-author" className="text-slate-500 dark:text-slate-400">
                                  {t('detail.ruleAuthor')}: {rule.author}
                                  {rule.license && <span className="text-slate-400"> ({rule.license})</span>}
                                </div>
                              )}
                            </div>
                          );
                        })()}

                        <div>
                          <div className="text-[11px] text-slate-400 mb-1">
                            {t('detail.snippet')}:
                          </div>
                          <pre
                            data-testid="violation-snippet"
                            className="p-2.5 rounded-lg bg-amber-50 dark:bg-amber-950/30 border-l-4 border-l-amber-400 text-slate-900 dark:text-slate-100 font-mono text-xs overflow-x-auto whitespace-pre-wrap break-all border border-slate-200/60 dark:border-slate-800"
                          >
                            {maskSnippet(violation.snippet)}
                          </pre>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </>
          )}
        </div>

        {/* Footer Actions */}
        <div className="px-6 py-4 border-t border-slate-100 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-800/40 flex items-center justify-between gap-3">
          <div className="text-xs text-slate-400">
            {event?.connector_type && (
              <span>Connector: {event.connector_type}</span>
            )}
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              data-testid="modal-close-btn"
              onClick={onClose}
              className="px-4 py-1.5 text-xs font-medium bg-slate-200 hover:bg-slate-300 dark:bg-slate-700 dark:hover:bg-slate-600 text-slate-800 dark:text-slate-100 rounded-lg transition-colors"
            >
              {t('detail.actions.close')}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
