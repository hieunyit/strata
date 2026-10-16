import React, { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Check, RotateCw, X } from 'lucide-react';
import { apiClient, Operation, Policy, PolicyVersion } from '../api/client';
import { usePolling } from '../usePolling';
import { PageShell } from './PageShell';
import { PageHeader, ErrorBanner, SectionTitle, Empty, formatTime } from '../components/ui';
import { useAuth } from '../context/AuthContext';
import { canApprovePolicies, canWritePolicies } from '../auth/roles';
import { PolicyDiff } from '../components/policy/PolicyDiff';
import { ReplayResult, ReplayState } from '../components/policy/ReplayResult';

const key = (v: PolicyVersion) => `${v.policy_id}@${v.version}`;

// by: "Name (sub)" or the subject; a hint only, the API decides
const isMine = (by: string | undefined, username: string | undefined) =>
  !!by && !!username && (by === username || by.endsWith(`(${username})`) || by.startsWith(`${username} (`));

// The review queue (W13-F-01): the versions submitted for review, each with
// its replay against the bundle in force and its diff against the approved
// version; approvers approve (once the replay is DONE, never their own) or
// reject with a reason.
export const ReviewsPage: React.FC = () => {
  const { t, i18n } = useTranslation();
  const { roles, username } = useAuth();
  const canApprove = canApprovePolicies(roles);
  const canReplay = canWritePolicies(roles);
  const queue = usePolling(() => apiClient.listVersionsByState('SUBMITTED'), 15000);
  const policies = usePolling(() => apiClient.listPolicies(), 0);
  const [selected, setSelected] = useState<PolicyVersion | null>(null);
  const [replays, setReplays] = useState<Record<string, Operation | undefined>>({});
  const [versions, setVersions] = useState<PolicyVersion[]>([]);
  const [comment, setComment] = useState('');
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<string | undefined>();
  const [done, setDone] = useState<string | undefined>();

  const list = queue.data ?? [];
  const policyOf = (id?: string): Policy | undefined => (policies.data ?? []).find((p) => p.id === id);

  // the replay state of every queued version
  useEffect(() => {
    let stop = false;
    void Promise.all(
      list.map(async (v) => [key(v), await apiClient.getVersionReplay(v.policy_id ?? '', v.version ?? 0).catch(() => undefined)] as const),
    ).then((rs) => {
      if (!stop) setReplays((cur) => ({ ...cur, ...Object.fromEntries(rs) }));
    });
    return () => {
      stop = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [queue.data]);

  const sel = selected ? replays[key(selected)] : undefined;

  // the selected version: its policy's versions (diff), and its replay until done
  useEffect(() => {
    if (!selected) return;
    let stop = false;
    void apiClient.listPolicyVersions(selected.policy_id ?? '').then((vs) => !stop && setVersions(vs)).catch(() => undefined);
    return () => {
      stop = true;
    };
  }, [selected]);
  useEffect(() => {
    if (!selected || sel?.done) return;
    const id = setInterval(async () => {
      const op = await apiClient.getVersionReplay(selected.policy_id ?? '', selected.version ?? 0).catch(() => undefined);
      setReplays((cur) => ({ ...cur, [key(selected)]: op }));
    }, 3000);
    return () => clearInterval(id);
  }, [selected, sel?.done]);

  const open = (v: PolicyVersion) => {
    setSelected(v);
    setVersions([]);
    setComment('');
    setActionError(undefined);
    setDone(undefined);
  };

  const act = async (what: 'approve' | 'reject' | 'replay') => {
    if (!selected) return;
    const id = selected.policy_id ?? '';
    const v = selected.version ?? 0;
    setBusy(true);
    setActionError(undefined);
    try {
      if (what === 'replay') {
        const op = await apiClient.replayPolicy(id, v);
        setReplays((cur) => ({ ...cur, [key(selected)]: op }));
      } else {
        if (what === 'approve') await apiClient.approvePolicy(id, v, comment.trim());
        else await apiClient.rejectPolicy(id, v, comment.trim());
        setDone(t(what === 'approve' ? 'reviews.approved' : 'reviews.rejected', { name: policyOf(id)?.name ?? id, version: v }));
        setSelected(null);
        void queue.refresh();
      }
    } catch (e) {
      setActionError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const mine = selected && (isMine(selected.created_by, username) || isMine(selected.submitted_by, username));
  const replayDone = sel?.state === 'DONE';
  const approveBlocked = !replayDone ? t('reviews.needReplay') : mine ? t('reviews.ownVersion') : undefined;
  const policy = policyOf(selected?.policy_id);
  const base = policy?.approved_version || undefined;

  return (
    <PageShell active="reviews">
      <PageHeader title={t('reviews.title')} description={t('reviews.subtitle')} />
      <ErrorBanner message={queue.error && t('common.refreshError', { error: queue.error })} />
      {done && (
        <p className="mb-3 text-[13px] text-ok" role="status" data-testid="review-done">
          {done}
        </p>
      )}
      <div className="panel mb-5 overflow-x-auto">
        <table className="w-full text-[13px]" data-testid="reviews-table">
          <thead>
            <tr className="border-b border-line bg-sunken/50">
              <th className="th">{t('reviews.col.policy')}</th>
              <th className="th text-right">{t('reviews.col.version')}</th>
              <th className="th">{t('reviews.col.submittedBy')}</th>
              <th className="th">{t('reviews.col.submitted')}</th>
              <th className="th">{t('reviews.col.replay')}</th>
            </tr>
          </thead>
          <tbody>
            {queue.loading && (
              <tr>
                <td colSpan={5} className="td py-8 text-center text-muted">{t('common.loading')}</td>
              </tr>
            )}
            {!queue.loading && list.length === 0 && (
              <tr>
                <td colSpan={5} className="td py-8 text-center text-muted" data-testid="reviews-empty">{t('reviews.empty')}</td>
              </tr>
            )}
            {list.map((v) => (
              <tr
                key={key(v)}
                data-testid="review-row"
                data-policy={v.policy_id}
                tabIndex={0}
                onClick={() => open(v)}
                onKeyDown={(e) => e.key === 'Enter' && open(v)}
                aria-selected={selected ? key(selected) === key(v) : false}
                className={`border-b border-line last:border-0 cursor-pointer hover:bg-sunken/70 ${selected && key(selected) === key(v) ? 'bg-accent/5' : ''}`}
              >
                <td className="td font-medium">{policyOf(v.policy_id)?.name ?? v.policy_id}</td>
                <td className="td text-right tabular-nums">v{v.version}</td>
                <td className="td text-muted">{v.submitted_by}</td>
                <td className="td text-muted whitespace-nowrap">{formatTime(v.submit_time, i18n.language, t('common.never'))}</td>
                <td className="td">
                  <ReplayState op={replays[key(v)]} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {selected && (
        <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_22rem]" data-testid="review-detail">
          <div className="space-y-5">
            <section className="panel">
              <SectionTitle aside={<ReplayState op={sel} />}>
                {t('reviews.replayOf', { name: policy?.name ?? selected.policy_id, version: selected.version })}
              </SectionTitle>
              <div className="p-4">
                <ReplayResult op={sel} />
                {canReplay && (sel === undefined || sel.state === 'FAILED') && (
                  <button type="button" className="btn mt-3" disabled={busy} onClick={() => void act('replay')} data-testid="review-replay">
                    <RotateCw className="w-3.5 h-3.5" />
                    {t('reviews.replayAgain')}
                  </button>
                )}
              </div>
            </section>
            {versions.length >= 2 ? (
              <PolicyDiff
                key={key(selected)}
                name={policy?.name ?? selected.policy_id ?? ''}
                versions={versions}
                initialFrom={base}
                initialTo={selected.version}
              />
            ) : (
              versions.length === 1 && (
                <section className="panel">
                  <Empty testId="review-new-policy">{t('reviews.newPolicy')}</Empty>
                </section>
              )
            )}
          </div>

          <section className="panel self-start" data-testid="review-decision">
            <SectionTitle>{t('reviews.decision')}</SectionTitle>
            <div className="space-y-3 p-4 text-[13px]">
              <p className="text-muted">
                {t('reviews.by', { created: selected.created_by, submitted: selected.submitted_by })}
              </p>
              {canApprove ? (
                <>
                  <label className="block">
                    <span className="label">{t('reviews.comment')}</span>
                    <textarea
                      className="field mt-1 w-full"
                      rows={3}
                      maxLength={1000}
                      value={comment}
                      onChange={(e) => setComment(e.target.value)}
                      data-testid="review-comment"
                    />
                  </label>
                  {approveBlocked && (
                    <p className="text-xs text-muted" data-testid="review-blocked">
                      {approveBlocked}
                    </p>
                  )}
                  <ErrorBanner message={actionError} testId="review-error" />
                  <div className="flex gap-2">
                    <button
                      type="button"
                      className="btn btn-primary"
                      disabled={busy || !!approveBlocked}
                      onClick={() => void act('approve')}
                      data-testid="review-approve"
                    >
                      <Check className="w-3.5 h-3.5" />
                      {t('reviews.approve')}
                    </button>
                    <button
                      type="button"
                      className="btn"
                      disabled={busy || comment.trim() === ''}
                      title={comment.trim() === '' ? t('reviews.reasonRequired') : undefined}
                      onClick={() => void act('reject')}
                      data-testid="review-reject"
                    >
                      <X className="w-3.5 h-3.5" />
                      {t('reviews.reject')}
                    </button>
                  </div>
                </>
              ) : (
                <p className="text-muted" data-testid="review-readonly">
                  {t('reviews.readOnly')}
                </p>
              )}
            </div>
          </section>
        </div>
      )}
    </PageShell>
  );
};
