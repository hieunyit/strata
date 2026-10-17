import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { StaticAuthProvider } from '../context/AuthContext';
import { ReplaySummary, replayCount, reviewableReplay } from '../components/policy/ReplaySummary';
import type { Operation } from '../api/client';
import i18n from '../i18n';

const op: Operation = { id: 'op-example', kind: 'REPLAY', policy_id: 'example-api', version: 2, state: 'DONE', done: true,
  replay: { samples: '18446744073709551615', input_digest: 'a'.repeat(64), draft_sha256: 'b'.repeat(64), baseline_sha256: 'c'.repeat(64), replay_sha256: 'd'.repeat(64),
    traffic: { samples: '18446744073709551615', newly_blocked: '3', examples_blocked: [{ method: 'GET', raw_uri: '/example?private=1' }] } } };
const show = (operation?: Operation, viewer = false, unavailable = false) => render(<StaticAuthProvider roles={[viewer ? 'viewer' : 'approver']}><ReplaySummary operation={operation} unavailable={unavailable} /></StaticAuthProvider>);

describe('replay evidence', () => {
  it('keeps unsigned 64-bit values exact and rejects malformed counters', () => {
    expect(replayCount('18446744073709551615')).toBe(18446744073709551615n);
    for (const bad of ['18446744073709551616', '-1', '1e3', '01', '1.5', 'x']) expect(replayCount(bad)).toBeUndefined();
    expect(replayCount()).toBe(0n);
  });
  it('requires a completed nonempty report with artifact provenance for approval', () => {
    expect(reviewableReplay(op)).toBe(true);
    for (const bad of [{ ...op, state: 'RUNNING' }, { ...op, done: false }, { ...op, replay: { ...op.replay, samples: '0' } }, { ...op, replay: { samples: '1' } }, { ...op, replay: { ...op.replay, traffic: { samples: '-1' } } }, { ...op, replay: { ...op.replay, samples: '1' } }]) expect(reviewableReplay(bad)).toBe(false);
  });
  it('renders exact counters and escapes request examples; viewer sees no snippets', async () => {
    await i18n.changeLanguage('en');
    const view = show(op);
    expect(screen.getAllByText(/18446744073709551615/)).toHaveLength(2);
    expect(screen.getByText(/private=1/)).toBeInTheDocument();
    view.unmount(); show(op, true);
    expect(screen.queryByText(/private=1/)).not.toBeInTheDocument();
  });
  it('distinguishes missing, failed and unavailable without exposing raw errors', async () => {
    await i18n.changeLanguage('en');
    const view = show(); expect(screen.getByText('No replay has been queued for this version.')).toBeInTheDocument();
    view.rerender(<StaticAuthProvider roles={['approver']}><ReplaySummary unavailable /></StaticAuthProvider>);
    expect(screen.getByRole('alert')).toHaveTextContent('Replay could not be loaded');
    view.rerender(<StaticAuthProvider roles={['approver']}><ReplaySummary operation={{ ...op, state: 'FAILED', error: 'private-path' }} /></StaticAuthProvider>);
    expect(screen.getByRole('alert')).toHaveTextContent('Replay failed'); expect(screen.queryByText('private-path')).not.toBeInTheDocument();
  });
});
