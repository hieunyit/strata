import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { DestructiveConfirmModal } from '../components/layout/DestructiveConfirmModal';

describe('DestructiveConfirmModal (Safeguards for Destructive Actions)', () => {
  it('enforces typed confirmation matching and minimum reason length', async () => {
    const onConfirm = vi.fn().mockResolvedValue(undefined);
    const onClose = vi.fn();

    render(
      <DestructiveConfirmModal
        title="Revoke Node Certificate: edge-node-01"
        description="Permanently invalidates mTLS certificates for this proxy node."
        expectedMatch="node-xyz-123"
        requireReason={true}
        minReasonLength={10}
        onConfirm={onConfirm}
        onClose={onClose}
      />
    );

    const matchInput = screen.getByTestId('destructive-match-input');
    const reasonInput = screen.getByTestId('destructive-reason-input');
    const confirmBtn = screen.getByTestId('destructive-confirm-btn') as HTMLButtonElement;
    const cancelBtn = screen.getByTestId('destructive-cancel-btn');

    // Initially disabled
    expect(confirmBtn.disabled).toBe(true);

    // Typing mismatched confirmation string
    fireEvent.change(matchInput, { target: { value: 'wrong-node' } });
    expect(confirmBtn.disabled).toBe(true);

    // Typing matched confirmation string, but no reason
    fireEvent.change(matchInput, { target: { value: 'node-xyz-123' } });
    expect(confirmBtn.disabled).toBe(true);

    // Typing reason with less than 10 characters
    fireEvent.change(reasonInput, { target: { value: 'Too short' } }); // 9 chars
    expect(confirmBtn.disabled).toBe(true);

    // Typing valid reason >= 10 characters
    fireEvent.change(reasonInput, { target: { value: 'Decommissioning compromised server edge-node-01' } });
    expect(confirmBtn.disabled).toBe(false);

    // Click confirm -> invokes onConfirm with reason
    fireEvent.click(confirmBtn);

    await waitFor(() => {
      expect(onConfirm).toHaveBeenCalledWith('Decommissioning compromised server edge-node-01');
      expect(onClose).toHaveBeenCalled();
    });

    // Clicking cancel invokes onClose
    fireEvent.click(cancelBtn);
    expect(onClose).toHaveBeenCalledTimes(2);
  });
});
