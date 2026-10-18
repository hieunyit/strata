import React, { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { apiClient } from '../api/client';
import { useReviewRead } from '../components/policy/useReviewRead';
import { VersionReview } from '../components/policy/VersionReview';
import { PageShell } from './PageShell';
import { PageHeader, formatTime } from '../components/ui';

export const ReviewsPage: React.FC = () => {
  const { t, i18n } = useTranslation();
  const queue = useReviewRead('submitted', signal => apiClient.listSubmittedPolicyVersions(signal));
  const [selected, setSelected] = useState<{ id: string; version: number }>();
  const [page, setPage] = useState(0);
  const rows = queue.data ?? [], lastPage = Math.max(0, Math.ceil(rows.length / 50) - 1), currentPage = Math.min(page, lastPage);
  return <PageShell active="reviews">
    <PageHeader title={t('reviews.title')} description={t('reviews.subtitle')}
      actions={<button className="btn" type="button" onClick={queue.refresh}>{t('reviews.refresh')}</button>} />
    {queue.error && <p role="alert">{t('reviews.unavailable')}</p>}
    {queue.loading && !queue.data && <p role="status">{t('reviews.loading')}</p>}
    {queue.data && <>
      <div className="panel overflow-x-auto mb-4"><table className="w-full text-[13px]" data-testid="reviews-table"><thead><tr>
        {['policy', 'version', 'submittedBy', 'submittedAt', 'inspect'].map(k => <th className="th" key={k}>{t(`reviews.${k}`)}</th>)}
      </tr></thead><tbody>
        {rows.slice(currentPage * 50, currentPage * 50 + 50).map(v => <tr key={`${v.policy_id}:${v.version}`} className="border-t border-line" data-testid="review-row">
          <td className="td break-all">{v.policy_id}</td><td className="td">v{v.version}</td><td className="td">{v.submitted_by || '—'}</td>
          <td className="td">{formatTime(v.submit_time, i18n.language, t('common.never'))}</td>
          <td className="td"><button type="button" className="btn" onClick={() => setSelected({ id: v.policy_id!, version: v.version! })}>{t('reviews.inspect')}</button></td>
        </tr>)}
        {rows.length === 0 && <tr><td colSpan={5} className="td">{t('reviews.empty')}</td></tr>}
      </tbody></table></div>
      <div className="flex flex-wrap items-center gap-3 mb-4">
        <button type="button" className="btn" disabled={currentPage === 0} onClick={() => setPage(currentPage - 1)}>{t('reviews.previous')}</button>
        <span>{t('reviews.page', { page: currentPage + 1, pages: lastPage + 1, total: rows.length })}</span>
        <button type="button" className="btn" disabled={currentPage === lastPage} onClick={() => setPage(currentPage + 1)}>{t('reviews.next')}</button>
      </div>
    </>}
    {selected && <VersionReview key={`${selected.id}:${selected.version}`} policyId={selected.id} version={selected.version} />}
  </PageShell>;
};
