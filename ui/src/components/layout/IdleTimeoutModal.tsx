import React, { useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { AlertTriangle, Clock } from 'lucide-react';

export interface IdleTimeoutModalProps {
  isOpen: boolean;
  secondsRemaining: number;
  onStaySignedIn: () => void;
  onSignOut: () => void;
}

export const IdleTimeoutModal: React.FC<IdleTimeoutModalProps> = ({
  isOpen,
  secondsRemaining,
  onStaySignedIn,
  onSignOut,
}) => {
  const { t } = useTranslation();

  // Pressing Escape or Enter can trigger stay signed in
  useEffect(() => {
    if (!isOpen) return;
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onStaySignedIn();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onStaySignedIn]);

  if (!isOpen) return null;

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="idle-timeout-title"
      data-testid="idle-timeout-modal"
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4"
    >
      <div className="panel max-w-md w-full p-6 shadow-xl border border-line bg-surface text-ink animate-in fade-in zoom-in-95 duration-150">
        <div className="flex items-start gap-3.5 mb-4">
          <div className="p-2 rounded-full bg-shadow/20 text-shadow shrink-0">
            <AlertTriangle className="w-5 h-5" />
          </div>
          <div className="min-w-0 flex-1">
            <h2 id="idle-timeout-title" className="text-base font-semibold leading-snug">
              {t('auth.idleWarningTitle', 'Session Expiring Soon')}
            </h2>
            <p className="mt-1 text-sm text-muted">
              {t('auth.idleWarningMessage', {
                seconds: secondsRemaining,
                defaultValue: `You have been inactive. For your security, your session will automatically end in ${secondsRemaining} seconds.`,
              })}
            </p>
          </div>
        </div>

        <div className="flex items-center justify-center gap-2 my-4 py-3 px-4 rounded-md bg-sunken/60 border border-line">
          <Clock className="w-4 h-4 text-shadow animate-pulse" />
          <span className="text-2xl font-mono font-bold tabular-nums text-shadow" data-testid="idle-seconds">
            {secondsRemaining}s
          </span>
        </div>

        <div className="mt-6 flex flex-col-reverse sm:flex-row items-center justify-end gap-2.5">
          <button
            type="button"
            className="btn w-full sm:w-auto"
            data-testid="idle-logout-btn"
            onClick={onSignOut}
          >
            {t('auth.idleLogout', 'Sign out now')}
          </button>
          <button
            type="button"
            className="btn-primary w-full sm:w-auto"
            data-testid="idle-stay-btn"
            onClick={onStaySignedIn}
            autoFocus
          >
            {t('auth.idleStay', 'Stay signed in')}
          </button>
        </div>
      </div>
    </div>
  );
};
