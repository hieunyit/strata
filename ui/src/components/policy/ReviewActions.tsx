import React, { useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { apiClient, Operation, PolicyVersion } from '../../api/client';
import { useAuth } from '../../context/AuthContext';
import { canApprovePolicies, canWritePolicies } from '../../auth/roles';
import { reviewableReplay } from './ReplaySummary';

export type ReviewAction = 'submitted' | 'approved' | 'rejected' | 'replayed';
export const ReviewActions: React.FC<{ version: PolicyVersion; operation?: Operation; disabled?: boolean; onChanged: (action: ReviewAction) => void }> = ({ version: v, operation, disabled, onChanged }) => {
  const { t } = useTranslation(), { roles, scoped, policyPermissions } = useAuth();
  const writer = canWritePolicies(roles) && (!scoped || !!policyPermissions?.[v.policy_id ?? '']?.includes('policies:write')), reviewer = canApprovePolicies(roles) && (!scoped || !!policyPermissions?.[v.policy_id ?? '']?.includes('policies:approve'));
  const [comment, setComment] = useState(''), [busy, setBusy] = useState(false), [failed, setFailed] = useState(false);
  const locked = useRef(false);
  const [reviewed, setReviewed] = useState<string>();
  const id = v.policy_id, number = v.version;
  if (!id || !number || (!writer && !reviewer)) return null;
  const invalid = Array.from(comment).length > 1000 || comment.includes('\0');
  const blocked = disabled || busy || failed;
  const run = async (action: ReviewAction) => {
    if (locked.current || blocked) return;
    locked.current = true; setBusy(true);
    try {
      if (action === 'submitted') await apiClient.submitPolicy(id, number);
      if (action === 'replayed') await apiClient.replayPolicy(id, number);
      if (action === 'approved') {
        if (!reviewableReplay(operation) || reviewed !== operation.id) { setFailed(true); return; }
        await apiClient.approvePolicy(id, number, comment.trim(), operation.id);
      }
      if (action === 'rejected') await apiClient.rejectPolicy(id, number, comment.trim());
      onChanged(action);
    } catch { setFailed(true); }
    finally { setBusy(false); }
    // Every outcome needs a fresh server snapshot before another write.
    // The parent remounts this component only on an explicit reload/success.
  };
  return <div className="border-t border-line pt-3 space-y-3" data-testid="review-actions">
    {failed && <p role="alert">{t('reviews.writeFailed')}</p>}
    {busy && <p role="status">{t('reviews.saving')}</p>}
    {reviewer && v.state === 'SUBMITTED' && <>
      <label className="block text-[13px]">{t('reviews.comment')}
        <textarea className="field w-full mt-1" rows={3} maxLength={2000} value={comment} disabled={blocked} onChange={e => setComment(e.target.value)} />
      </label>
      {invalid && <p role="alert">{t('reviews.commentLimit')}</p>}
      {!reviewableReplay(operation) && <p className="text-muted text-[13px]">{t('reviews.needReplay')}</p>}
      {reviewableReplay(operation) && <label className="flex items-start gap-2 text-[13px] break-all">
        <input type="checkbox" checked={reviewed === operation.id} disabled={blocked} onChange={e => setReviewed(e.target.checked ? operation.id : undefined)} />
        {t('reviews.reviewed', { id: operation.id })}
      </label>}
      <div className="flex flex-wrap gap-3">
        <button type="button" className="btn btn-primary" disabled={blocked || invalid || !reviewableReplay(operation) || reviewed !== operation.id} onClick={() => void run('approved')}>{t('reviews.approve')}</button>
        <button type="button" className="btn" disabled={blocked || invalid || !comment.trim()} onClick={() => void run('rejected')}>{t('reviews.reject')}</button>
      </div>
    </>}
    {writer && <div className="flex flex-wrap gap-3">
      {(v.state === 'DRAFT' || v.state === 'REJECTED') && <button type="button" className="btn btn-primary" disabled={blocked} onClick={() => void run('submitted')}>{t('reviews.submit')}</button>}
      <button type="button" className="btn" disabled={blocked || operation?.state === 'PENDING' || operation?.state === 'RUNNING'} onClick={() => void run('replayed')}>{t('reviews.runReplay')}</button>
    </div>}
  </div>;
};
