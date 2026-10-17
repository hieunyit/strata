import React, { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { AlertOctagon, Loader2 } from 'lucide-react';
import { ErrorBanner } from '../ui';

export interface DestructiveConfirmModalProps {
  title: string;
  description: React.ReactNode;
  /** Exact string the user must type to confirm (e.g. resource name, node ID, or CONFIRM) */
  expectedMatch: string;
  /** Label explaining what to type */
  matchLabel?: string;
  /** Whether a reason is required for audit logs (default: true) */
  requireReason?: boolean;
  /** Minimum reason character length (default: 10) */
  minReasonLength?: number;
  confirmLabel?: string;
  cancelLabel?: string;
  onConfirm: (reason: string) => Promise<void> | void;
  onClose: () => void;
}

export const DestructiveConfirmModal: React.FC<DestructiveConfirmModalProps> = ({
  title,
  description,
  expectedMatch,
  matchLabel,
  requireReason = true,
  minReasonLength = 10,
  confirmLabel,
  cancelLabel,
  onConfirm,
  onClose,
}) => {
  const { t } = useTranslation();
  const ref = useRef<HTMLDialogElement>(null);
  const [typedMatch, setTypedMatch] = useState('');
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    const d = ref.current;
    if (!d) return;
    if (typeof d.showModal === 'function') {
      if (!d.open) d.showModal();
    } else {
      d.setAttribute('open', '');
    }
  }, []);

  const isMatchValid = typedMatch.trim() === expectedMatch;
  const isReasonValid = !requireReason || reason.trim().length >= minReasonLength;
  const canSubmit = isMatchValid && isReasonValid && !busy;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!canSubmit) return;
    setBusy(true);
    setError('');
    try {
      await onConfirm(reason.trim());
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <dialog
      ref={ref}
      onClose={onClose}
      onCancel={onClose}
      data-testid="destructive-confirm-dialog"
      className="panel w-[min(32rem,calc(100vw-2rem))] p-0 text-ink backdrop:bg-black/50"
    >
      <form onSubmit={handleSubmit} className="p-6 space-y-4">
        <div className="flex items-start gap-3">
          <div className="p-2 rounded-full bg-block/15 text-block shrink-0 mt-0.5">
            <AlertOctagon className="w-5 h-5" />
          </div>
          <div className="min-w-0 flex-1">
            <h2 className="text-[16px] font-semibold text-block" data-testid="destructive-title">
              {title}
            </h2>
            <div className="mt-1 text-[13px] text-muted space-y-1">
              {description}
            </div>
          </div>
        </div>

        {error && <ErrorBanner message={error} onClose={() => setError('')} testId="destructive-error" />}

        <div className="space-y-1.5 pt-1">
          <label className="label text-[13px]" htmlFor="destructive-match-input">
            {matchLabel || (
              <span>
                {t('common.typeToConfirm', 'To confirm, type')}{' '}
                <code className="font-mono font-bold text-ink px-1 py-0.5 rounded bg-sunken">
                  {expectedMatch}
                </code>{' '}
                {t('common.below', 'below:')}
              </span>
            )}
          </label>
          <input
            id="destructive-match-input"
            type="text"
            className="field font-mono text-[13px] w-full"
            data-testid="destructive-match-input"
            value={typedMatch}
            onChange={(e) => setTypedMatch(e.target.value)}
            placeholder={expectedMatch}
            disabled={busy}
            autoComplete="off"
            spellCheck={false}
          />
        </div>

        {requireReason && (
          <div className="space-y-1.5">
            <div className="flex items-center justify-between">
              <label className="label text-[13px]" htmlFor="destructive-reason-input">
                {t('common.auditReason', 'Reason (required for audit log):')}
              </label>
              <span
                className={`text-[11px] tabular-nums ${
                  reason.trim().length >= minReasonLength ? 'text-ok' : 'text-muted'
                }`}
                data-testid="destructive-reason-counter"
              >
                {reason.trim().length} / {minReasonLength}
              </span>
            </div>
            <textarea
              id="destructive-reason-input"
              className="field text-[13px] w-full min-h-[4rem] resize-y"
              data-testid="destructive-reason-input"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder={t('common.reasonPlaceholder', 'Explain why this action is taken…')}
              disabled={busy}
              rows={2}
            />
          </div>
        )}

        <div className="mt-6 flex flex-col-reverse sm:flex-row items-center justify-end gap-2.5 pt-2">
          <button
            type="button"
            className="btn w-full sm:w-auto"
            data-testid="destructive-cancel-btn"
            onClick={onClose}
            disabled={busy}
          >
            {cancelLabel || t('common.cancel', 'Cancel')}
          </button>
          <button
            type="submit"
            className="btn-danger w-full sm:w-auto inline-flex items-center justify-center gap-1.5 px-4"
            data-testid="destructive-confirm-btn"
            disabled={!canSubmit}
            aria-disabled={!canSubmit}
          >
            {busy && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
            {confirmLabel || t('common.confirm', 'Confirm')}
          </button>
        </div>
      </form>
    </dialog>
  );
};
