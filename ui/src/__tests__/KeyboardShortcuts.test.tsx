import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import React, { useState } from 'react';
import { useKeyboardShortcuts } from '../hooks/useKeyboardShortcuts';
import { KeyboardHelpModal } from '../components/layout/KeyboardHelpModal';
import i18n from '../i18n';

const TestComponent: React.FC<{
  onSearchFocus?: () => void;
  onEscape?: () => void;
}> = ({ onSearchFocus, onEscape }) => {
  const [helpOpen, setHelpOpen] = useState(false);

  useKeyboardShortcuts({
    onSearchFocus,
    onEscape: () => {
      onEscape?.();
      setHelpOpen(false);
    },
    onHelpToggle: () => setHelpOpen((prev) => !prev),
  });

  return (
    <div>
      <input data-testid="test-input" type="text" />
      <div data-testid="help-status">{helpOpen ? 'open' : 'closed'}</div>
      <KeyboardHelpModal isOpen={helpOpen} onClose={() => setHelpOpen(false)} />
    </div>
  );
};

beforeEach(() => {
  void i18n.changeLanguage('en');
});

describe('KeyboardShortcuts and Modal', () => {
  it('toggles help modal when ? is pressed outside input, and closes on Escape', () => {
    const onEscape = vi.fn();
    render(<TestComponent onEscape={onEscape} />);

    expect(screen.getByTestId('help-status').textContent).toBe('closed');
    expect(screen.queryByTestId('keyboard-help-dialog')).toBeNull();

    // Press '?'
    fireEvent.keyDown(window, { key: '?' });
    expect(screen.getByTestId('help-status').textContent).toBe('open');
    expect(screen.getByTestId('keyboard-help-dialog')).not.toBeNull();
    expect(screen.getByText('Keyboard Shortcuts')).not.toBeNull();

    // Press Escape
    fireEvent.keyDown(window, { key: 'Escape' });
    expect(screen.getByTestId('help-status').textContent).toBe('closed');
    expect(onEscape).toHaveBeenCalledTimes(1);
  });

  it('triggers onSearchFocus when / is pressed outside input', () => {
    const onSearchFocus = vi.fn();
    render(<TestComponent onSearchFocus={onSearchFocus} />);

    fireEvent.keyDown(window, { key: '/' });
    expect(onSearchFocus).toHaveBeenCalledTimes(1);
  });

  it('does NOT trigger / or ? shortcuts when user is focused inside an input element', () => {
    const onSearchFocus = vi.fn();
    render(<TestComponent onSearchFocus={onSearchFocus} />);

    const input = screen.getByTestId('test-input');
    input.focus();

    fireEvent.keyDown(input, { key: '/' });
    fireEvent.keyDown(input, { key: '?' });

    expect(onSearchFocus).not.toHaveBeenCalled();
    expect(screen.getByTestId('help-status').textContent).toBe('closed');
  });
});
