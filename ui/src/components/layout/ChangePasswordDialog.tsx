import React, { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { apiClient } from '../../api/client';

const MIN_PASSWORD = 12;

// A local account changes its own password; its other sessions end.
export const ChangePasswordDialog: React.FC<{ onClose: () => void }> = ({ onClose }) => {
  const { t } = useTranslation();
  const ref = useRef<HTMLDialogElement>(null);
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [again, setAgain] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [done, setDone] = useState(false);

  useEffect(() => {
    const d = ref.current;
    if (!d) return;
    // showModal traps focus and closes on Escape; without it (jsdom) the
    // dialog is simply shown.
    if (typeof d.showModal === 'function') {
      if (!d.open) d.showModal();
    } else {
      d.setAttribute('open', '');
    }
  }, []);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (next !== again) {
      setError(t('account.mismatch'));
      return;
    }
    setBusy(true);
    setError('');
    try {
      await apiClient.changePassword(current, next);
      setDone(true);
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
      data-testid="change-password-dialog"
      className="panel w-[min(26rem,calc(100vw-2rem))] p-0 text-ink backdrop:bg-black/40"
    >
      <form onSubmit={submit} className="p-5 space-y-3">
        <h2 className="text-[15px] font-semibold">{t('account.title')}</h2>
        {done ? (
          <p data-testid="change-password-done" className="text-[13px]">{t('account.done')}</p>
        ) : (
          <>
            <div>
              <label htmlFor="cur-password" className="label">{t('account.current')}</label>
              <input id="cur-password" data-testid="cur-password" type="password" className="field" autoComplete="current-password"
                required value={current} onChange={(e) => setCurrent(e.target.value)} />
            </div>
            <div>
              <label htmlFor="next-password" className="label">{t('account.next', { min: MIN_PASSWORD })}</label>
              <input id="next-password" data-testid="next-password" type="password" className="field" autoComplete="new-password"
                required minLength={MIN_PASSWORD} value={next} onChange={(e) => setNext(e.target.value)} />
            </div>
            <div>
              <label htmlFor="again-password" className="label">{t('account.again')}</label>
              <input id="again-password" data-testid="again-password" type="password" className="field" autoComplete="new-password"
                required value={again} onChange={(e) => setAgain(e.target.value)} />
            </div>
            {error && <p role="alert" data-testid="change-password-error" className="text-[13px] text-block">{error}</p>}
          </>
        )}
        <div className="flex justify-end gap-2 pt-1">
          <button type="button" className="btn" onClick={onClose}>{done ? t('common.close') : t('common.cancel')}</button>
          {!done && (
            <button type="submit" data-testid="change-password-btn" className="btn-primary"
              disabled={busy || !current || next.length < MIN_PASSWORD || !again}>
              {t('account.submit')}
            </button>
          )}
        </div>
      </form>
    </dialog>
  );
};
