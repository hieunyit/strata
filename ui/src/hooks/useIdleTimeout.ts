import { useEffect, useRef, useState, useCallback } from 'react';

export interface UseIdleTimeoutOptions {
  /** Total idle time in milliseconds before timeout triggers (default: 15 min) */
  timeoutMs?: number;
  /** Warning countdown duration before timeout in milliseconds (default: 60 sec) */
  warningMs?: number;
  /** Whether the idle tracker is currently active (e.g. user is authenticated) */
  enabled?: boolean;
  /** Callback triggered when countdown reaches zero */
  onTimeout: () => void;
  /** Optional callback triggered when user confirms activity or resets timer */
  onActive?: () => void;
}

export interface UseIdleTimeoutReturn {
  isWarningOpen: boolean;
  secondsRemaining: number;
  staySignedIn: () => void;
  signOutNow: () => void;
  resetTimer: () => void;
}

const DEFAULT_TIMEOUT_MS = 15 * 60 * 1000; // 15 minutes
const DEFAULT_WARNING_MS = 60 * 1000; // 60 seconds
const THROTTLE_MS = 1000;

export function useIdleTimeout({
  timeoutMs = DEFAULT_TIMEOUT_MS,
  warningMs = DEFAULT_WARNING_MS,
  enabled = true,
  onTimeout,
  onActive,
}: UseIdleTimeoutOptions): UseIdleTimeoutReturn {
  const [isWarningOpen, setIsWarningOpen] = useState(false);
  const [secondsRemaining, setSecondsRemaining] = useState(Math.round(warningMs / 1000));

  const lastActiveRef = useRef<number>(Date.now());
  const warningOpenRef = useRef<boolean>(false);
  warningOpenRef.current = isWarningOpen;

  const onTimeoutRef = useRef(onTimeout);
  onTimeoutRef.current = onTimeout;

  const onActiveRef = useRef(onActive);
  onActiveRef.current = onActive;

  const staySignedIn = useCallback(() => {
    lastActiveRef.current = Date.now();
    setIsWarningOpen(false);
    setSecondsRemaining(Math.round(warningMs / 1000));
    onActiveRef.current?.();
  }, [warningMs]);

  const signOutNow = useCallback(() => {
    setIsWarningOpen(false);
    onTimeoutRef.current();
  }, []);

  const resetTimer = useCallback(() => {
    lastActiveRef.current = Date.now();
    if (warningOpenRef.current) {
      setIsWarningOpen(false);
      setSecondsRemaining(Math.round(warningMs / 1000));
    }
  }, [warningMs]);

  useEffect(() => {
    if (!enabled) {
      setIsWarningOpen(false);
      return;
    }

    lastActiveRef.current = Date.now();

    const handleUserActivity = () => {
      // Do not silently dismiss warning modal on passive events if warning is already open
      if (warningOpenRef.current) return;

      const now = Date.now();
      if (now - lastActiveRef.current > THROTTLE_MS) {
        lastActiveRef.current = now;
      }
    };

    const events: (keyof WindowEventMap)[] = ['mousedown', 'mousemove', 'keydown', 'scroll', 'touchstart'];
    for (const evt of events) {
      window.addEventListener(evt, handleUserActivity, { passive: true });
    }

    const intervalId = window.setInterval(() => {
      const now = Date.now();
      const idleTime = now - lastActiveRef.current;

      if (idleTime >= timeoutMs) {
        setIsWarningOpen(false);
        onTimeoutRef.current();
      } else if (idleTime >= timeoutMs - warningMs) {
        const remainingMs = timeoutMs - idleTime;
        const secs = Math.max(0, Math.ceil(remainingMs / 1000));
        setIsWarningOpen(true);
        setSecondsRemaining(secs);
      } else if (warningOpenRef.current) {
        setIsWarningOpen(false);
      }
    }, 1000);

    return () => {
      for (const evt of events) {
        window.removeEventListener(evt, handleUserActivity);
      }
      window.clearInterval(intervalId);
    };
  }, [enabled, timeoutMs, warningMs]);

  return {
    isWarningOpen,
    secondsRemaining,
    staySignedIn,
    signOutNow,
    resetTimer,
  };
}
