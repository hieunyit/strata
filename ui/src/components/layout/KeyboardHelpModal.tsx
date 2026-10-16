import React, { useEffect, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import { Keyboard, X } from 'lucide-react';

export interface KeyboardHelpModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const KeyboardHelpModal: React.FC<KeyboardHelpModalProps> = ({ isOpen, onClose }) => {
  const { t } = useTranslation();
  const ref = useRef<HTMLDialogElement>(null);

  useEffect(() => {
    const d = ref.current;
    if (!d) return;
    if (isOpen) {
      if (typeof d.showModal === 'function') {
        if (!d.open) d.showModal();
      } else {
        d.setAttribute('open', '');
      }
    } else {
      if (typeof d.close === 'function') {
        if (d.open) d.close();
      } else {
        d.removeAttribute('open');
      }
    }
  }, [isOpen]);

  if (!isOpen) return null;

  const shortcuts = [
    { key: '/', description: t('shortcuts.search', 'Focus Block ID search bar') },
    { key: 'Esc', description: t('shortcuts.escape', 'Close open modal or drawer') },
    { key: '?', description: t('shortcuts.help', 'Toggle this keyboard shortcuts dialog') },
  ];

  return (
    <dialog
      ref={ref}
      onClose={onClose}
      onCancel={onClose}
      data-testid="keyboard-help-dialog"
      className="panel w-[min(28rem,calc(100vw-2rem))] p-0 text-ink backdrop:bg-black/50"
    >
      <div className="p-5 space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-line">
          <div className="flex items-center gap-2">
            <Keyboard className="w-5 h-5 text-accent" />
            <h2 className="text-[15px] font-semibold">{t('shortcuts.title', 'Keyboard Shortcuts')}</h2>
          </div>
          <button
            type="button"
            className="btn p-1.5 h-auto text-muted hover:text-ink"
            onClick={onClose}
            aria-label={t('common.close', 'Close')}
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <ul className="space-y-2.5 text-[13px]">
          {shortcuts.map((s, idx) => (
            <li key={idx} className="flex items-center justify-between py-1 border-b border-line/50 last:border-0">
              <span className="text-muted">{s.description}</span>
              <kbd className="font-mono text-xs px-2 py-0.5 rounded bg-sunken border border-line text-ink font-semibold">
                {s.key}
              </kbd>
            </li>
          ))}
        </ul>

        <div className="pt-2 flex justify-end">
          <button type="button" className="btn text-xs" onClick={onClose}>
            {t('common.close', 'Close')}
          </button>
        </div>
      </div>
    </dialog>
  );
};
