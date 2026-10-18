import React, { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { apiClient, ApiError } from '../../api/client';
import { PolicyDiff } from './PolicyDiff';
import { ReplaySummary } from './ReplaySummary';
import { ReviewActions, ReviewAction } from './ReviewActions';
import { useReviewRead } from './useReviewRead';

export const VersionReview: React.FC<{ policyId: string; version: number; onChanged?: () => void }> = ({ policyId, version, onChanged }) => {
  const { t } = useTranslation();
  const [revision, setRevision] = useState(0), [result, setResult] = useState<ReviewAction>();
  const reload = () => setRevision(n => n + 1);
  const read = useReviewRead(`${policyId}:${version}:${revision}`, async signal => {
    const [versions, operation] = await Promise.all([apiClient.listPolicyVersions(policyId, signal), apiClient.getVersionReplay(policyId, version, signal)]);
    const candidate = versions.find(v => v.policy_id === policyId && v.version === version);
    if (!candidate?.spec || !candidate.state) throw new ApiError('Version missing', 502);
    const baseline = versions.filter(v => v.policy_id === policyId && (v.state === 'APPROVED' || v.state === 'DEPLOYED') && v.version !== version)
      .sort((a, b) => (b.version ?? 0) - (a.version ?? 0))[0];
    return { candidate, baseline, operation };
  });
  return <section className="panel p-4 space-y-4 min-w-0" data-testid="version-review">
    <div className="flex flex-wrap items-center justify-between gap-3">
      <h2 className="font-semibold break-all">{policyId} · v{version}</h2>
      <button type="button" className="btn" onClick={reload}>{t('reviews.refresh')}</button>
    </div>
    {result && <p role="status">{t(`reviews.result.${result}`)}</p>}
    {read.error && <p role="alert">{t('reviews.unavailable')}</p>}
    {read.loading && <p role="status">{t('reviews.loading')}</p>}
    {read.data && <>
      <p>{t(`editor.state.${read.data.candidate.state}`)} · {t('reviews.author', { name: read.data.candidate.created_by || '—' })} · {t('reviews.submitter', { name: read.data.candidate.submitted_by || '—' })}</p>
      <p className="text-muted text-[13px]">{t('reviews.fourEyes')}</p>
      {read.data.baseline ? <>
        <p>{t('reviews.diffBaseline', { version: read.data.baseline.version })}</p>
        <PolicyDiff key={`${read.data.baseline.version}:${version}`} name={policyId} versions={[read.data.baseline, read.data.candidate]}
          fromVersion={read.data.baseline.version} toVersion={version} fixed onClose={() => {}} />
      </> : <div><p>{t('reviews.firstVersion')}</p><pre className="text-xs whitespace-pre-wrap break-all mt-2">{JSON.stringify(read.data.candidate.spec, null, 2)}</pre></div>}
      <ReplaySummary operation={read.data.operation} />
      <ReviewActions key={revision} version={read.data.candidate} operation={read.data.operation} disabled={read.loading || read.error}
        onChanged={action => { setResult(action); reload(); onChanged?.(); }} />
    </>}
  </section>;
};
