import React, { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { ChevronLeft, SearchX, CheckCircle, ShieldAlert, AlertTriangle, FileSpreadsheet, Ban, Check } from 'lucide-react';
import { AppShell } from '../components/layout/AppShell';
import { ErrorBanner, VerdictBadge, relativeTime } from '../components/ui';
import { EventTrace, CopyButton } from '../components/events/EventTrace';
import { apiClient, ApiError, GetEventResponse, Exception } from '../api/client';
import { useAuth } from '../context/AuthContext';
import { href } from '../router';

type State =
  | { kind: 'loading' }
  | { kind: 'found'; data: GetEventResponse }
  | { kind: 'missing' }
  | { kind: 'failed'; message: string };

// One event, opened from the table, the top bar's Block ID lookup or a
// link (#/events/STR-...): the helpdesk's page.
export const EventDetailPage: React.FC<{ blockId: string }> = ({ blockId }) => {
  const { t, i18n } = useTranslation();
  const auth = useAuth();
  const [state, setState] = useState<State>({ kind: 'loading' });
  const id = blockId.trim().toUpperCase();

  // Action states
  const [fpMarked, setFpMarked] = useState(false);
  const [fpReason, setFpReason] = useState('');
  const [showFpModal, setShowFpModal] = useState(false);
  const [fpSubmitting, setFpSubmitting] = useState(false);

  const [exception, setException] = useState<Exception | undefined>();
  const [showExceptionModal, setShowExceptionModal] = useState(false);
  const [exceptionTtl, setExceptionTtl] = useState(14 * 86400); // 14 days default
  const [exceptionReason, setExceptionReason] = useState('');
  const [exceptionSubmitting, setExceptionSubmitting] = useState(false);

  const [blockedTarget, setBlockedTarget] = useState(false);
  const [showBlockModal, setShowBlockModal] = useState(false);
  const [blockReason, setBlockReason] = useState('');

  const [actionError, setActionError] = useState<string | undefined>();
  const [actionSuccess, setActionSuccess] = useState<string | undefined>();

  useEffect(() => {
    let alive = true;
    setState({ kind: 'loading' });
    apiClient
      .getEvent(id)
      .then((data) => {
        if (!alive) return;
        setState({ kind: 'found', data });
        if ((data.event as { false_positive?: boolean }).false_positive) {
          setFpMarked(true);
        }
      })
      .catch((err: unknown) => {
        if (!alive) return;
        if (err instanceof ApiError && err.code === 404) setState({ kind: 'missing' });
        else if (err instanceof ApiError) setState({ kind: 'failed', message: t('errors.blockIdLookup', { error: err.message }) });
        else setState({ kind: 'failed', message: t('errors.blockIdConnection', { id }) });
      });
    return () => {
      alive = false;
    };
  }, [id, t]);

  const ev = state.kind === 'found' ? state.data.event : undefined;

  // Narrowest scope values for exception modal
  const ruleId = ev?.violations?.[0]?.rule_id ?? ev?.matched_rules?.[0] ?? 0;
  const field = ev?.violations?.[0]?.field || '*';
  const policyId = ev?.policy_id || 'default';
  const targetIdentity = ev?.client_ip || ev?.identity || id;

  const handleMarkFp = async () => {
    if (!fpReason.trim()) return;
    setFpSubmitting(true);
    setActionError(undefined);
    try {
      await apiClient.markFalsePositive(id, fpReason.trim());
      setFpMarked(true);
      setShowFpModal(false);
      setActionSuccess(t('detail.actions.fpMarked'));
    } catch (err) {
      setActionError(err instanceof Error ? err.message : String(err));
    } finally {
      setFpSubmitting(false);
    }
  };

  const handleCreateException = async () => {
    if (!exceptionReason.trim()) return;
    setExceptionSubmitting(true);
    setActionError(undefined);
    try {
      const exp = await apiClient.createExceptionFromBlockId(id, exceptionTtl, exceptionReason.trim());
      setException(exp);
      setShowExceptionModal(false);
      setActionSuccess(t('detail.actions.exceptionCreated', { id: exp.id }));
    } catch (err) {
      setActionError(err instanceof Error ? err.message : String(err));
    } finally {
      setExceptionSubmitting(false);
    }
  };

  const handleApproveException = async () => {
    if (!exception) return;
    setActionError(undefined);
    try {
      const approved = await apiClient.approveException(exception.id);
      setException(approved);
      setActionSuccess(t('detail.actions.exceptionApproved', { id: approved.id }));
    } catch (err) {
      setActionError(err instanceof Error ? err.message : String(err));
    }
  };

  const handleBlockIdentity = () => {
    setBlockedTarget(true);
    setShowBlockModal(false);
    setActionSuccess(`Đã chặn đối tượng ${targetIdentity}`);
  };

  // Four-Eyes rule: creator cannot self-approve
  const isCreator = Boolean(
    exception &&
      auth?.username &&
      (exception.created_by === auth.username || exception.created_by.includes(auth.username))
  );

  return (
    <AppShell active="event" wide>
      <a href={href({ page: 'events' })} className="mb-3 inline-flex items-center gap-1 text-[13px] text-muted hover:text-ink" data-testid="back-to-events">
        <ChevronLeft className="w-4 h-4" />
        {t('detail.back')}
      </a>

      <div className="mb-6 flex flex-wrap items-center justify-between gap-y-3">
        <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
          <h1 className="font-mono text-[22px] font-medium tracking-tight" data-testid="detail-block-id">
            {id}
          </h1>
          {ev && <VerdictBadge action={ev.action} size="md" />}
          {fpMarked && (
            <span
              data-testid="badge-fp-marked"
              className="inline-flex items-center gap-1 rounded bg-emerald-500/10 px-2 py-0.5 text-xs font-medium text-emerald-600 dark:text-emerald-400 border border-emerald-500/20"
            >
              <CheckCircle className="w-3.5 h-3.5" />
              {t('detail.actions.fpMarked')}
            </span>
          )}
          {blockedTarget && (
            <span
              data-testid="badge-blocked-identity"
              className="inline-flex items-center gap-1 rounded bg-rose-500/10 px-2 py-0.5 text-xs font-medium text-rose-600 dark:text-rose-400 border border-rose-500/20"
            >
              <Ban className="w-3.5 h-3.5" />
              Đã chặn
            </span>
          )}
          <CopyButton text={id} label={t('detail.copyId')} testId="copy-block-id" />
          {ev && <span className="text-[13px] text-muted">{relativeTime(ev.timestamp, i18n.language)}</span>}
        </div>

        {/* Action Buttons Toolbar */}
        {ev && (
          <div className="flex flex-wrap items-center gap-2" data-testid="event-actions-toolbar">
            <button
              type="button"
              data-testid="btn-mark-fp"
              onClick={() => setShowFpModal(true)}
              disabled={fpMarked}
              className="inline-flex items-center gap-1.5 rounded border border-line bg-surface px-3 py-1.5 text-xs font-medium hover:bg-sunken disabled:opacity-50"
            >
              <Check className="w-3.5 h-3.5 text-emerald-500" />
              {t('detail.actions.markFp')}
            </button>
            <button
              type="button"
              data-testid="btn-create-exception"
              onClick={() => setShowExceptionModal(true)}
              className="inline-flex items-center gap-1.5 rounded border border-line bg-surface px-3 py-1.5 text-xs font-medium hover:bg-sunken"
            >
              <FileSpreadsheet className="w-3.5 h-3.5 text-sky-500" />
              {t('detail.actions.createException')}
            </button>
            <button
              type="button"
              data-testid="btn-block-identity"
              onClick={() => setShowBlockModal(true)}
              disabled={blockedTarget}
              className="inline-flex items-center gap-1.5 rounded border border-line bg-surface px-3 py-1.5 text-xs font-medium text-rose-600 hover:bg-rose-50 dark:hover:bg-rose-950/20 disabled:opacity-50"
            >
              <Ban className="w-3.5 h-3.5" />
              {t('detail.actions.blockIdentity')}
            </button>
          </div>
        )}
      </div>

      {actionSuccess && (
        <div className="mb-4 flex items-center gap-2 rounded bg-emerald-500/10 p-3 text-xs text-emerald-600 dark:text-emerald-400 border border-emerald-500/20" data-testid="action-success">
          <CheckCircle className="w-4 h-4 shrink-0" />
          <span>{actionSuccess}</span>
        </div>
      )}

      {actionError && <ErrorBanner message={actionError} testId="action-error" />}

      {/* Exception Status Card (if created) */}
      {exception && (
        <div className="panel mb-6 p-4 border border-sky-500/30 bg-sky-500/5" data-testid="exception-card">
          <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
            <div className="flex items-center gap-2">
              <FileSpreadsheet className="w-4 h-4 text-sky-500" />
              <span className="font-mono text-sm font-semibold">{exception.id}</span>
              <span className={`inline-flex rounded px-2 py-0.5 text-xs font-medium ${
                exception.state === 'APPROVED' ? 'bg-emerald-500/15 text-emerald-600' : 'bg-amber-500/15 text-amber-600'
              }`}>
                {exception.state === 'APPROVED' ? t('detail.actions.stateApproved') : t('detail.actions.stateSubmitted')}
              </span>
            </div>
            {exception.state === 'SUBMITTED' && (
              <div>
                {isCreator ? (
                  <span
                    data-testid="btn-approve-disabled"
                    className="text-xs text-muted italic flex items-center gap-1 cursor-not-allowed"
                    title={t('detail.actions.cannotSelfApprove')}
                  >
                    <AlertTriangle className="w-3.5 h-3.5 text-amber-500" />
                    {t('detail.actions.cannotSelfApprove')}
                  </span>
                ) : (
                  <button
                    type="button"
                    data-testid="btn-approve-exception"
                    onClick={handleApproveException}
                    className="inline-flex items-center gap-1 rounded bg-sky-600 px-3 py-1 text-xs font-medium text-white hover:bg-sky-500"
                  >
                    <Check className="w-3.5 h-3.5" />
                    {t('detail.actions.approve')}
                  </button>
                )}
              </div>
            )}
          </div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
            <div>
              <span className="text-muted block">Policy:</span>
              <span className="font-mono">{exception.policy_id}</span>
            </div>
            <div>
              <span className="text-muted block">Rule ID:</span>
              <span className="font-mono">{exception.rule_id}</span>
            </div>
            <div>
              <span className="text-muted block">Field:</span>
              <span className="font-mono">{exception.field}</span>
            </div>
            <div>
              <span className="text-muted block">Hết hạn:</span>
              <span>{new Date(exception.expires_at).toLocaleDateString()}</span>
            </div>
          </div>
        </div>
      )}

      {state.kind === 'loading' && <p className="text-[13px] text-muted">{t('detail.loading')}</p>}
      {state.kind === 'failed' && <ErrorBanner message={state.message} testId="error-banner" />}
      {state.kind === 'missing' && (
        <div className="panel px-6 py-10 text-center" data-testid="event-missing">
          <SearchX className="mx-auto mb-3 w-8 h-8 text-faint" />
          <p className="text-[15px] font-medium">{t('errors.blockIdNotFound', { id })}</p>
          <p className="mt-1 text-[13px] text-muted max-w-[60ch] mx-auto">{t('detail.missingHelp')}</p>
        </div>
      )}
      {state.kind === 'found' && <EventTrace event={state.data.event} rules={state.data.rules} />}

      {/* Modal 1: Mark False Positive */}
      {showFpModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4" data-testid="modal-mark-fp">
          <div className="panel w-full max-w-md p-6 bg-surface border border-line rounded-lg shadow-xl">
            <h3 className="text-base font-semibold mb-3 flex items-center gap-2">
              <CheckCircle className="w-4 h-4 text-emerald-500" />
              {t('detail.actions.fpDialogTitle')}
            </h3>
            <p className="text-xs text-muted mb-4">
              Xác nhận đánh dấu sự kiện {id} là False Positive. Số liệu này sẽ cập nhật bảng sức khỏe rule và giảm trọng số cảnh báo.
            </p>
            <div className="mb-4">
              <label className="block text-xs font-medium text-ink mb-1">
                {t('detail.actions.fpReasonLabel')} <span className="text-rose-500">*</span>
              </label>
              <textarea
                data-testid="fp-reason-input"
                rows={3}
                className="w-full rounded border border-line bg-sunken p-2 text-xs focus:outline-none focus:ring-1 focus:ring-sky-500"
                placeholder={t('detail.actions.fpReasonPlaceholder')}
                value={fpReason}
                onChange={(e) => setFpReason(e.target.value)}
              />
            </div>
            <div className="flex justify-end gap-2">
              <button
                type="button"
                className="px-3 py-1.5 text-xs rounded border border-line hover:bg-sunken"
                onClick={() => setShowFpModal(false)}
              >
                {t('detail.actions.cancel')}
              </button>
              <button
                type="button"
                data-testid="submit-mark-fp"
                disabled={!fpReason.trim() || fpSubmitting}
                className="px-3 py-1.5 text-xs rounded bg-emerald-600 text-white font-medium hover:bg-emerald-500 disabled:opacity-50"
                onClick={handleMarkFp}
              >
                {fpSubmitting ? 'Đang gửi...' : t('detail.actions.confirm')}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Modal 2: Create Exception */}
      {showExceptionModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4" data-testid="modal-create-exception">
          <div className="panel w-full max-w-lg p-6 bg-surface border border-line rounded-lg shadow-xl">
            <h3 className="text-base font-semibold mb-2 flex items-center gap-2">
              <FileSpreadsheet className="w-4 h-4 text-sky-500" />
              {t('detail.actions.exceptionDialogTitle')}
            </h3>
            <p className="text-xs text-muted mb-4">
              Sinh rule exception có phạm vi hẹp nhất dựa trên vi phạm thực tế để bỏ qua kiểm tra, có thời hạn cố định.
            </p>

            <div className="grid grid-cols-3 gap-3 mb-4 bg-sunken p-3 rounded border border-line text-xs">
              <div>
                <span className="text-muted block">{t('detail.actions.exceptionPolicyLabel')}:</span>
                <span className="font-mono font-medium">{policyId}</span>
              </div>
              <div>
                <span className="text-muted block">{t('detail.actions.exceptionRuleLabel')}:</span>
                <span className="font-mono font-medium">{ruleId}</span>
              </div>
              <div>
                <span className="text-muted block">{t('detail.actions.exceptionFieldLabel')}:</span>
                <span className="font-mono font-medium">{field}</span>
              </div>
            </div>

            <div className="mb-4">
              <label className="block text-xs font-medium text-ink mb-1">
                {t('detail.actions.exceptionTtlLabel')} <span className="text-rose-500">*</span>
              </label>
              <select
                data-testid="exception-ttl-select"
                className="w-full rounded border border-line bg-sunken p-2 text-xs focus:outline-none focus:ring-1 focus:ring-sky-500"
                value={exceptionTtl}
                onChange={(e) => setExceptionTtl(Number(e.target.value))}
              >
                <option value={7 * 86400}>{t('detail.actions.ttl7')}</option>
                <option value={14 * 86400}>{t('detail.actions.ttl14')}</option>
                <option value={30 * 86400}>{t('detail.actions.ttl30')}</option>
              </select>
            </div>

            <div className="mb-4">
              <label className="block text-xs font-medium text-ink mb-1">
                {t('detail.actions.exceptionReasonLabel')} <span className="text-rose-500">*</span>
              </label>
              <input
                type="text"
                data-testid="exception-reason-input"
                className="w-full rounded border border-line bg-sunken p-2 text-xs focus:outline-none focus:ring-1 focus:ring-sky-500"
                placeholder="Lý do chi tiết bỏ qua kiểm tra cho tham số này..."
                value={exceptionReason}
                onChange={(e) => setExceptionReason(e.target.value)}
              />
            </div>

            <div className="flex justify-end gap-2">
              <button
                type="button"
                className="px-3 py-1.5 text-xs rounded border border-line hover:bg-sunken"
                onClick={() => setShowExceptionModal(false)}
              >
                {t('detail.actions.cancel')}
              </button>
              <button
                type="button"
                data-testid="submit-create-exception"
                disabled={!exceptionReason.trim() || exceptionSubmitting}
                className="px-3 py-1.5 text-xs rounded bg-sky-600 text-white font-medium hover:bg-sky-500 disabled:opacity-50"
                onClick={handleCreateException}
              >
                {exceptionSubmitting ? 'Đang tạo...' : t('detail.actions.confirm')}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Modal 3: Block IP / Identity */}
      {showBlockModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4" data-testid="modal-block-identity">
          <div className="panel w-full max-w-md p-6 bg-surface border border-line rounded-lg shadow-xl">
            <h3 className="text-base font-semibold mb-2 flex items-center gap-2 text-rose-600">
              <Ban className="w-4 h-4" />
              {t('detail.actions.blockDialogTitle')}
            </h3>
            <p className="text-xs text-muted mb-4">
              Xác nhận chặn toàn bộ request từ đối tượng vi phạm này.
            </p>

            <div className="mb-3 bg-rose-500/10 p-2.5 rounded border border-rose-500/20 text-xs font-mono">
              <span className="text-muted block text-[11px] mb-0.5">{t('detail.actions.blockTargetLabel')}:</span>
              <span className="font-semibold text-rose-600 dark:text-rose-400">{targetIdentity}</span>
            </div>

            <div className="mb-4">
              <label className="block text-xs font-medium text-ink mb-1">
                {t('detail.actions.blockReasonLabel')} <span className="text-rose-500">*</span>
              </label>
              <input
                type="text"
                data-testid="block-reason-input"
                className="w-full rounded border border-line bg-sunken p-2 text-xs focus:outline-none focus:ring-1 focus:ring-rose-500"
                placeholder="Lý do chặn khẩn cấp..."
                value={blockReason}
                onChange={(e) => setBlockReason(e.target.value)}
              />
            </div>

            <div className="flex justify-end gap-2">
              <button
                type="button"
                className="px-3 py-1.5 text-xs rounded border border-line hover:bg-sunken"
                onClick={() => setShowBlockModal(false)}
              >
                {t('detail.actions.cancel')}
              </button>
              <button
                type="button"
                data-testid="submit-block-identity"
                disabled={!blockReason.trim()}
                className="px-3 py-1.5 text-xs rounded bg-rose-600 text-white font-medium hover:bg-rose-500 disabled:opacity-50"
                onClick={handleBlockIdentity}
              >
                {t('detail.actions.confirm')}
              </button>
            </div>
          </div>
        </div>
      )}
    </AppShell>
  );
};
