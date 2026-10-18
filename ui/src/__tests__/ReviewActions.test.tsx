import { act, fireEvent, render, screen } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ReviewActions } from '../components/policy/ReviewActions';
import { apiClient, ApiError, Operation, PolicyVersion } from '../api/client';
import { StaticAuthProvider } from '../context/AuthContext';
import type { UserRole } from '../auth/roles';
import i18n from '../i18n';

const v: PolicyVersion = { policy_id: 'example-api', version: 2, state: 'SUBMITTED' };
const op: Operation = { id: 'op-viewed', kind: 'REPLAY', policy_id: 'example-api', version: 2, state: 'DONE', done: true,
  replay: { samples: '1', corpus: { samples: '1' }, input_digest: 'a'.repeat(64), draft_sha256: 'b'.repeat(64), baseline_sha256: 'c'.repeat(64), replay_sha256: 'd'.repeat(64) } };
const changed = vi.fn();
const form = (role: UserRole = 'approver', version = v, operation: Operation | undefined = op, disabled = false) => <StaticAuthProvider roles={[role]}><ReviewActions version={version} operation={operation} onChanged={changed} disabled={disabled} /></StaticAuthProvider>;
beforeEach(async () => { vi.restoreAllMocks(); changed.mockReset(); await i18n.changeLanguage('en'); });
describe('version decisions', () => {
  it('only offers writes allowed by the role and state', () => {
    const viewer = render(form('viewer')); expect(screen.queryByTestId('review-actions')).not.toBeInTheDocument(); viewer.unmount();
    const operator = render(form('operator', { ...v, state: 'DRAFT' })); expect(screen.getByRole('button', { name: 'Submit for review' })).toBeInTheDocument(); expect(screen.queryByRole('button', { name: 'Approve version' })).not.toBeInTheDocument(); operator.unmount();
    render(form()); expect(screen.getByRole('button', { name: 'Approve version' })).toBeDisabled(); expect(screen.queryByRole('button', { name: 'Run replay' })).not.toBeInTheDocument();
  });
  it('pins the acknowledged report once and blocks synchronous double submit', async () => {
    let finish!: (v: PolicyVersion) => void;
    const approve = vi.spyOn(apiClient, 'approvePolicy').mockImplementation(() => new Promise(resolve => { finish = resolve; }));
    render(form()); fireEvent.change(screen.getByRole('textbox'), { target: { value: 'reviewed evidence' } });
    fireEvent.click(screen.getByRole('checkbox'));
    const button = screen.getByRole('button', { name: 'Approve version' }); fireEvent.click(button); fireEvent.click(button);
    expect(approve).toHaveBeenCalledTimes(1); expect(approve).toHaveBeenCalledWith('example-api', 2, 'reviewed evidence', 'op-viewed');
    await act(async () => finish({ ...v, state: 'APPROVED' })); expect(changed).toHaveBeenCalledWith('approved');
  });
  it('requires a new acknowledgement when polling replaces the report', () => {
    const view = render(form()); fireEvent.click(screen.getByRole('checkbox')); expect(screen.getByRole('button', { name: 'Approve version' })).toBeEnabled();
    view.rerender(form('approver', v, { ...op, id: 'op-new' })); expect(screen.getByRole('checkbox')).not.toBeChecked(); expect(screen.getByRole('button', { name: 'Approve version' })).toBeDisabled();
  });
  it.each([400, 503])('keeps a stale/uncertain write locked until reload and never retries unpinned (%i)', async (code) => {
    const approve = vi.spyOn(apiClient, 'approvePolicy').mockRejectedValue(new ApiError('private detail', code));
    render(form()); fireEvent.click(screen.getByRole('checkbox')); fireEvent.click(screen.getByRole('button', { name: 'Approve version' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Reload review');
    expect(screen.queryByText('private detail')).not.toBeInTheDocument(); expect(screen.getByRole('button', { name: 'Approve version' })).toBeDisabled(); expect(approve).toHaveBeenCalledTimes(1); expect(changed).not.toHaveBeenCalled();
  });
  it('allows rejection during replay only with a bounded reason', async () => {
    const reject = vi.spyOn(apiClient, 'rejectPolicy').mockResolvedValue({ ...v, state: 'REJECTED' });
    render(form('approver', v, { ...op, state: 'RUNNING' }));
    const button = screen.getByRole('button', { name: 'Reject version' }); expect(button).toBeDisabled();
    fireEvent.change(screen.getByRole('textbox'), { target: { value: '😀'.repeat(1001) } }); expect(button).toBeDisabled();
    fireEvent.change(screen.getByRole('textbox'), { target: { value: 'needs revision' } }); fireEvent.click(button);
    await act(async () => {}); expect(reject).toHaveBeenCalledWith('example-api', 2, 'needs revision'); expect(changed).toHaveBeenCalledWith('rejected');
  });
  it('submits the selected draft version and disables writes during a read', async () => {
    const submit = vi.spyOn(apiClient, 'submitPolicy').mockResolvedValue(v);
    const view = render(form('operator', { ...v, state: 'DRAFT' }, undefined, true)); expect(screen.getByRole('button', { name: 'Submit for review' })).toBeDisabled();
    view.rerender(form('operator', { ...v, state: 'DRAFT' })); fireEvent.click(screen.getByRole('button', { name: 'Submit for review' }));
    await act(async () => {}); expect(submit).toHaveBeenCalledWith('example-api', 2); expect(changed).toHaveBeenCalledWith('submitted');
  });
});
