import React from 'react';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, act } from '@testing-library/react';
import { useIdleTimeout } from '../hooks/useIdleTimeout';
import { IdleTimeoutModal } from '../components/layout/IdleTimeoutModal';

const TestHost: React.FC<{
  timeoutMs?: number;
  warningMs?: number;
  onTimeout: () => void;
  onActive?: () => void;
}> = ({ timeoutMs = 5000, warningMs = 2000, onTimeout, onActive }) => {
  const { isWarningOpen, secondsRemaining, staySignedIn, signOutNow } = useIdleTimeout({
    timeoutMs,
    warningMs,
    enabled: true,
    onTimeout,
    onActive,
  });

  return (
    <div>
      <div data-testid="warning-state">{isWarningOpen ? 'OPEN' : 'CLOSED'}</div>
      <div data-testid="seconds-state">{secondsRemaining}</div>
      <IdleTimeoutModal
        isOpen={isWarningOpen}
        secondsRemaining={secondsRemaining}
        onStaySignedIn={staySignedIn}
        onSignOut={signOutNow}
      />
    </div>
  );
};

describe('IdleTimeout & Inactivity Lock (PCI-DSS v4.0)', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('triggers warning when idle threshold is reached, then logs out on expiry', () => {
    const onTimeout = vi.fn();
    const onActive = vi.fn();

    render(<TestHost timeoutMs={5000} warningMs={2000} onTimeout={onTimeout} onActive={onActive} />);

    expect(screen.getByTestId('warning-state').textContent).toBe('CLOSED');
    expect(screen.queryByTestId('idle-timeout-modal')).toBeNull();

    // Advance 3000ms: threshold (5000 - 2000) reached, warning opens with 2s remaining
    act(() => {
      vi.advanceTimersByTime(3100);
    });

    expect(screen.getByTestId('warning-state').textContent).toBe('OPEN');
    expect(screen.getByTestId('idle-timeout-modal')).toBeDefined();
    expect(screen.getByTestId('idle-seconds').textContent).toBe('2s');

    // Advance 1000ms: 1s remaining
    act(() => {
      vi.advanceTimersByTime(1000);
    });
    expect(screen.getByTestId('idle-seconds').textContent).toBe('1s');

    // Advance 1000ms: expires -> onTimeout called
    act(() => {
      vi.advanceTimersByTime(1000);
    });
    expect(onTimeout).toHaveBeenCalledTimes(1);
  });

  it('allows user to stay signed in and resets the timer', () => {
    const onTimeout = vi.fn();
    const onActive = vi.fn();

    render(<TestHost timeoutMs={5000} warningMs={2000} onTimeout={onTimeout} onActive={onActive} />);

    // Advance to warning state
    act(() => {
      vi.advanceTimersByTime(3100);
    });
    expect(screen.getByTestId('warning-state').textContent).toBe('OPEN');

    // User clicks "Stay signed in"
    const stayBtn = screen.getByTestId('idle-stay-btn');
    act(() => {
      fireEvent.click(stayBtn);
    });

    expect(screen.getByTestId('warning-state').textContent).toBe('CLOSED');
    expect(onActive).toHaveBeenCalledTimes(1);
    expect(onTimeout).not.toHaveBeenCalled();

    // Another 2000ms idle does not expire because timer was reset
    act(() => {
      vi.advanceTimersByTime(2000);
    });
    expect(screen.getByTestId('warning-state').textContent).toBe('CLOSED');
    expect(onTimeout).not.toHaveBeenCalled();
  });

  it('allows user to sign out immediately from the warning dialog', () => {
    const onTimeout = vi.fn();

    render(<TestHost timeoutMs={5000} warningMs={2000} onTimeout={onTimeout} />);

    act(() => {
      vi.advanceTimersByTime(3100);
    });
    expect(screen.getByTestId('warning-state').textContent).toBe('OPEN');

    const logoutBtn = screen.getByTestId('idle-logout-btn');
    act(() => {
      fireEvent.click(logoutBtn);
    });

    expect(onTimeout).toHaveBeenCalledTimes(1);
  });
});
