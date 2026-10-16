import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { StaticAuthProvider } from '../context/AuthContext';
import { ReviewsPage } from '../pages/ReviewsPage';
import { PoliciesPage } from '../pages/PoliciesPage';
import { apiClient, ApiError, Operation, Policy, PolicyVersion } from '../api/client';
import { parseRoute } from '../router';
import i18n from '../i18n';

const policy: Policy = { id: 'example-api', name: 'example-api', version: 3, approved_version: 2, etag: 'e3', spec: { mode: 'MODE_ENFORCE' } };
const submitted: PolicyVersion = {
  policy_id: 'example-api', version: 3, state: 'SUBMITTED', spec: { mode: 'MODE_ENFORCE' },
  created_by: 'lab-operator', submitted_by: 'lab-operator', submit_time: '2026-10-16T08:00:00Z',
};
const versions: PolicyVersion[] = [
  submitted,
  { policy_id: 'example-api', version: 2, state: 'DEPLOYED', spec: { mode: 'MODE_SHADOW' }, created_by: 'lab-operator' },
];
const done: Operation = {
  id: 'op-1', state: 'DONE', done: true, policy_id: 'example-api', version: 3,
  replay: {
    baseline_bundle: '41', sample_files: 2,
    traffic: { samples: '1200', newly_blocked: '3', newly_allowed: '0', newly_blocked_rules: { '942100': '3' }, newly_blocked_paths: { '/v1/login': '3' } },
    corpus: { samples: '4281', newly_blocked: '1700', newly_allowed: '0', newly_blocked_rules: { '942100': '900' } },
  },
};

function setup(op: Operation | undefined) {
  vi.spyOn(apiClient, 'listVersionsByState').mockResolvedValue([submitted]);
  vi.spyOn(apiClient, 'listPolicies').mockResolvedValue([policy]);
  vi.spyOn(apiClient, 'listPolicyVersions').mockResolvedValue(versions);
  vi.spyOn(apiClient, 'getVersionReplay').mockResolvedValue(op);
}

async function openRow(roles: ('viewer' | 'operator' | 'approver' | 'admin')[], username: string) {
  render(<StaticAuthProvider roles={roles} username={username}><ReviewsPage /></StaticAuthProvider>);
  fireEvent.click(await screen.findByTestId('review-row'));
  await screen.findByTestId('review-detail');
}

beforeEach(() => {
  vi.restoreAllMocks();
  vi.spyOn(apiClient, 'getVersion').mockResolvedValue({ version: 'test', commit: '', api_version: 'v1' });
  void i18n.changeLanguage('en');
});

describe('review queue (W13-F-01)', () => {
  it('has a route', () => {
    expect(parseRoute('#/reviews')).toEqual({ page: 'reviews' });
  });

  it('shows the replay against the bundle in force and the diff against the approved version', async () => {
    setup(done);
    await openRow(['approver'], 'lab-approver');
    expect(await screen.findByTestId('replay-traffic-blocked')).toHaveTextContent('3');
    expect(screen.getByTestId('replay-corpus-blocked')).toHaveTextContent('1,700');
    expect(screen.getByTestId('replay-traffic-rules')).toHaveTextContent('942100');
    expect(screen.getByTestId('replay-traffic-paths')).toHaveTextContent('/v1/login');
    expect(await screen.findByTestId('diff-from')).toHaveValue('2');
    expect(screen.getByTestId('diff-to')).toHaveValue('3');
  });

  it('approves only once the replay is done', async () => {
    setup({ id: 'op-1', state: 'RUNNING', done: false });
    await openRow(['approver'], 'lab-approver');
    expect(screen.getByTestId('review-approve')).toBeDisabled();
    expect(screen.getByTestId('review-blocked')).toHaveTextContent('waits for the replay');
    expect(screen.getByTestId('replay-running')).toBeInTheDocument();
  });

  it('does not offer the approval of your own version', async () => {
    setup(done);
    await openRow(['admin'], 'lab-operator');
    await screen.findByTestId('replay-result');
    expect(screen.getByTestId('review-approve')).toBeDisabled();
    expect(screen.getByTestId('review-blocked')).toHaveTextContent('someone else');
  });

  it('approves with a comment, and reports what the API refuses', async () => {
    setup(done);
    const approve = vi.spyOn(apiClient, 'approvePolicy')
      .mockRejectedValueOnce(new ApiError('whoever drafted or submitted a version cannot approve it (four eyes)', 403))
      .mockResolvedValue({ ...submitted, state: 'APPROVED' });
    await openRow(['approver'], 'lab-approver');
    await screen.findByTestId('replay-result');
    fireEvent.change(screen.getByTestId('review-comment'), { target: { value: 'replay clean' } });
    fireEvent.click(screen.getByTestId('review-approve'));
    expect(await screen.findByTestId('review-error')).toHaveTextContent('four eyes');
    fireEvent.click(screen.getByTestId('review-approve'));
    expect(await screen.findByTestId('review-done')).toHaveTextContent('example-api v3 approved');
    expect(approve).toHaveBeenLastCalledWith('example-api', 3, 'replay clean');
  });

  it('rejects only with a reason, without waiting for the replay', async () => {
    setup({ id: 'op-1', state: 'PENDING', done: false });
    const reject = vi.spyOn(apiClient, 'rejectPolicy').mockResolvedValue({ ...submitted, state: 'REJECTED' });
    await openRow(['approver'], 'lab-approver');
    expect(screen.getByTestId('review-reject')).toBeDisabled();
    fireEvent.change(screen.getByTestId('review-comment'), { target: { value: '40 new blocks on /v1/login' } });
    fireEvent.click(screen.getByTestId('review-reject'));
    await waitFor(() => expect(reject).toHaveBeenCalledWith('example-api', 3, '40 new blocks on /v1/login'));
    expect(await screen.findByTestId('review-done')).toHaveTextContent('rejected');
  });

  it('lets an operator replay a version again, and viewers only read', async () => {
    setup({ id: 'op-1', state: 'FAILED', done: true, error: 'no corpus' });
    const replay = vi.spyOn(apiClient, 'replayPolicy').mockResolvedValue({ id: 'op-2', state: 'PENDING', done: false });
    await openRow(['operator'], 'lab-operator');
    expect(screen.getByTestId('replay-error')).toHaveTextContent('no corpus');
    expect(screen.getByTestId('review-readonly')).toBeInTheDocument();
    fireEvent.click(screen.getByTestId('review-replay'));
    await waitFor(() => expect(replay).toHaveBeenCalledWith('example-api', 3));
  });

  it('says when nothing waits', async () => {
    vi.spyOn(apiClient, 'listVersionsByState').mockResolvedValue([]);
    vi.spyOn(apiClient, 'listPolicies').mockResolvedValue([]);
    render(<StaticAuthProvider roles={['viewer']}><ReviewsPage /></StaticAuthProvider>);
    expect(await screen.findByTestId('reviews-empty')).toBeInTheDocument();
  });
});

describe('submit for review (W13-F-01)', () => {
  it('submits the newest draft', async () => {
    const draft: PolicyVersion = { ...submitted, state: 'DRAFT' };
    vi.spyOn(apiClient, 'listPolicies').mockResolvedValue([policy]);
    const list = vi.spyOn(apiClient, 'listPolicyVersions').mockResolvedValueOnce([draft, versions[1]]).mockResolvedValue(versions);
    const submit = vi.spyOn(apiClient, 'submitPolicy').mockResolvedValue(submitted);
    render(<StaticAuthProvider roles={['operator']}><PoliciesPage /></StaticAuthProvider>);
    fireEvent.click(await screen.findByTestId('policy-row'));
    fireEvent.click(await screen.findByTestId('policy-submit'));
    await waitFor(() => expect(submit).toHaveBeenCalledWith('example-api', 3));
    expect(await screen.findByTestId('policy-submitted')).toHaveTextContent('Version 3 submitted');
    expect(list).toHaveBeenCalledTimes(2);
    expect(screen.queryByTestId('policy-submit')).not.toBeInTheDocument();
  });

  it('is not offered to viewers, nor on older versions', async () => {
    vi.spyOn(apiClient, 'listPolicies').mockResolvedValue([policy]);
    vi.spyOn(apiClient, 'listPolicyVersions').mockResolvedValue([{ ...submitted, state: 'DRAFT' }, { ...versions[1], state: 'DRAFT' }]);
    render(<StaticAuthProvider roles={['viewer']}><PoliciesPage /></StaticAuthProvider>);
    fireEvent.click(await screen.findByTestId('policy-row'));
    await screen.findAllByTestId('policy-version-row');
    expect(screen.queryByTestId('policy-submit')).not.toBeInTheDocument();
  });
});
