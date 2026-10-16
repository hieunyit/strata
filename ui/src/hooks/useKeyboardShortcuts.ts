import { useEffect, useRef } from 'react';

export interface ShortcutHandlers {
  onSearchFocus?: () => void;
  onEscape?: () => void;
  onHelpToggle?: () => void;
}

export function useKeyboardShortcuts(handlers: ShortcutHandlers) {
  const handlersRef = useRef(handlers);
  handlersRef.current = handlers;

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      const activeTag = (document.activeElement?.tagName || '').toLowerCase();
      const isInput = activeTag === 'input' || activeTag === 'textarea' || activeTag === 'select';

      // Escape always triggers
      if (e.key === 'Escape') {
        handlersRef.current.onEscape?.();
        return;
      }

      // If user is currently typing in an input, do not trigger single-key shortcuts
      if (isInput) return;

      if (e.key === '/') {
        e.preventDefault();
        handlersRef.current.onSearchFocus?.();
      } else if (e.key === '?') {
        e.preventDefault();
        handlersRef.current.onHelpToggle?.();
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);
}
