import { act, render, screen } from '@testing-library/react';
import { beforeEach, expect, it } from 'vitest';
import { VersionDecision } from '../components/policy/VersionDecision';
import i18n from '../i18n';

beforeEach(async () => { await i18n.changeLanguage('en'); });
it('shows the rejection reason, actor and timestamp to the author reviewing a version', () => {
  render(<VersionDecision version={{ policy_id: 'example-api', version: 2, state: 'REJECTED', decided_by: 'example-reviewer', decide_time: '2026-10-18T00:00:00Z', decision_comment: 'Scope is too broad.\nLimit it to the intended route.' }} />);
  expect(screen.getByTestId('decision-reason')).toHaveTextContent('Scope is too broad. Limit it to the intended route.');
  expect(screen.getByText('example-reviewer')).toBeInTheDocument();
  expect(screen.getByText(/10\/18\/2026/).closest('time')).toHaveAttribute('dateTime', '2026-10-18T00:00:00Z');
});
it('distinguishes the replay used by approval from the latest operation and translates on render', async () => {
  render(<VersionDecision version={{ state: 'APPROVED', approved_replay_id: 'op-approved' }} latestReplayId="op-newer" />);
  expect(screen.getByTestId('approved-replay-id')).toHaveTextContent('op-approved');
  expect(screen.getByRole('note')).toHaveTextContent('does not replace the report used for approval');
  await act(async () => { await i18n.changeLanguage('vi'); });
  expect(screen.getByText('Replay dùng khi duyệt')).toBeInTheDocument();
  expect(screen.getByTestId('approved-replay-id')).toHaveTextContent('op-approved');
});
it('does not invent decision data for a draft or a proof mismatch for the approved operation', () => {
  const view = render(<VersionDecision version={{ state: 'DRAFT' }} />);
  expect(screen.queryByTestId('version-decision')).not.toBeInTheDocument();
  view.rerender(<VersionDecision version={{ state: 'APPROVED', approved_replay_id: 'op-approved' }} latestReplayId="op-approved" />);
  expect(screen.queryByRole('note')).not.toBeInTheDocument();
});
