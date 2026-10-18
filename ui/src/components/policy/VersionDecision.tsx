import React from 'react';
import { useTranslation } from 'react-i18next';
import type { PolicyVersion } from '../../api/client';
import { formatTime } from '../ui';

// The proof saved with approval is immutable. A later replay shown by the
// inspector must not look as if it replaced the report that was approved.
export const VersionDecision: React.FC<{ version: PolicyVersion; latestReplayId?: string }> = ({ version: v, latestReplayId }) => {
  const { t, i18n } = useTranslation();
  if (!v.decided_by && !v.decision_comment && !v.approved_replay_id) return null;
  return <section className="text-[13px] space-y-2 border-t border-line pt-3" data-testid="version-decision">
    <dl className="space-y-2">
      {v.decided_by && <div><dt className="font-medium">{t('reviews.decidedBy')}</dt><dd className="break-all">{v.decided_by}</dd></div>}
      {v.decide_time && <div><dt className="font-medium">{t('reviews.decidedAt')}</dt><dd><time dateTime={v.decide_time}>{formatTime(v.decide_time, i18n.language, t('common.never'))}</time></dd></div>}
      {v.decision_comment && <div><dt className="font-medium">{t('reviews.decisionReason')}</dt><dd className="whitespace-pre-wrap break-words" data-testid="decision-reason">{v.decision_comment}</dd></div>}
      {v.approved_replay_id && <div><dt className="font-medium">{t('reviews.approvalReplay')}</dt><dd className="font-mono text-xs break-all" data-testid="approved-replay-id">{v.approved_replay_id}</dd></div>}
    </dl>
    {v.approved_replay_id && latestReplayId && v.approved_replay_id !== latestReplayId && <p className="text-muted" role="note">{t('reviews.laterReplay')}</p>}
  </section>;
};
