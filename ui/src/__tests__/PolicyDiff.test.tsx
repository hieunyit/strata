// W12-F-01: pick two versions of a policy, see the diff block by block.
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, within } from '@testing-library/react';
import { StaticAuthProvider } from '../context/AuthContext';
import { PoliciesPage } from '../pages/PoliciesPage';
import { apiClient, Policy, PolicyVersion } from '../api/client';
import { diffSpecs } from '../lib/policyDiff';
import i18n from '../i18n';

beforeEach(() => {
  vi.restoreAllMocks();
  vi.spyOn(apiClient, 'getVersion').mockResolvedValue({ version: 'test', commit: '', api_version: 'v1' });
  void i18n.changeLanguage('en');
});

describe('diffSpecs', () => {
  it('lists every field of each block and marks the changed ones', () => {
    const d = diffSpecs(
      { mode: 'MODE_SHADOW', response: { data_guard: ['cccd'] } },
      { mode: 'MODE_ENFORCE', oversize: 'OVERSIZE_BLOCK', response: { db_errors: true, data_guard: ['jwt', 'cccd'] } },
    );
    expect(d.map((b) => [b.block, b.changed])).toEqual([
      ['general', 2],
      ['response', 2],
    ]);
    expect(d[0].fields[0]).toMatchObject({ key: 'mode', from: 'shadow', to: 'enforce', changed: true });
    expect(d[0].fields[1]).toMatchObject({ key: 'oversize', from: 'pass', to: 'block' });
    const g = d[1].fields.find((f) => f.key === 'data_guard');
    expect(g).toMatchObject({ from: '[cccd]', to: '[cccd, jwt]', added: ['jwt'], removed: [] });
    expect(d[1].fields.find((f) => f.key === 'allowed_codes_check')?.changed).toBe(false);
  });

  it('shows the canary in the general block', () => {
    const d = diffSpecs({ mode: 'MODE_ENFORCE', canary_percent: 1 }, { mode: 'MODE_ENFORCE', canary_percent: 5 });
    expect(d[0].fields.find((f) => f.key === 'canary_percent')).toMatchObject({ from: '1', to: '5', changed: true });
    expect(diffSpecs({ mode: 'MODE_ENFORCE' }, { mode: 'MODE_ENFORCE', canary_percent: 5 })[0].fields[2]).toMatchObject({ from: '—', to: '5' });
  });

  it('treats defaults the API leaves out, and list order, as equal', () => {
    const d = diffSpecs(
      { mode: 'MODE_UNSPECIFIED', oversize: 'OVERSIZE_UNSPECIFIED', response: { data_guard: ['jwt', 'cccd'] } },
      { mode: 'MODE_SHADOW', oversize: 'OVERSIZE_PASS', response: { allowed_codes_check: false, data_guard: ['cccd', 'jwt'] } },
    );
    expect(d.every((b) => b.changed === 0)).toBe(true);
  });
});

const policy: Policy = { id: 'example-api', name: 'example-api', version: 3, etag: 'e3', spec: { mode: 'MODE_ENFORCE' } };
const versions: PolicyVersion[] = [
  { policy_id: 'example-api', version: 3, spec: { mode: 'MODE_ENFORCE', response: { db_errors: true } }, state: 'DRAFT' },
  { policy_id: 'example-api', version: 2, spec: { mode: 'MODE_SHADOW', response: { db_errors: true } }, state: 'DEPLOYED' },
  { policy_id: 'example-api', version: 1, spec: { mode: 'MODE_SHADOW' }, state: 'DEPLOYED' },
];

async function openDiff(roles: ('viewer' | 'operator')[], vs = versions) {
  vi.spyOn(apiClient, 'listPolicies').mockResolvedValue([policy]);
  vi.spyOn(apiClient, 'listPolicyVersions').mockResolvedValue(vs);
  render(<StaticAuthProvider roles={roles}><PoliciesPage /></StaticAuthProvider>);
  fireEvent.click(await screen.findByTestId('policy-row'));
  await screen.findAllByTestId('policy-version-row');
}

const changedKeys = (block: string) =>
  within(screen.getByTestId(`diff-block-${block}`))
    .getAllByTestId('diff-field')
    .filter((r) => r.dataset.changed === 'true')
    .map((r) => r.querySelector('code')?.textContent);

describe('PoliciesPage: compare versions', () => {
  it('compares the latest version with the one before by default, and any two picked', async () => {
    await openDiff(['viewer']);
    fireEvent.click(screen.getByTestId('policy-compare'));
    const d = await screen.findByTestId('policy-diff');
    expect((screen.getByTestId('diff-from') as HTMLSelectElement).value).toBe('2');
    expect((screen.getByTestId('diff-to') as HTMLSelectElement).value).toBe('3');
    expect(within(d).getByTestId('diff-summary').textContent).toBe('1 field changed');
    expect(changedKeys('general')).toEqual(['mode']);
    expect(changedKeys('response')).toEqual([]);
    expect(within(screen.getByTestId('diff-block-response')).getByTestId('diff-block-count').textContent).toBe('unchanged');

    fireEvent.change(screen.getByTestId('diff-from'), { target: { value: '1' } });
    expect(screen.getByTestId('diff-summary').textContent).toBe('2 fields changed');
    expect(changedKeys('response')).toEqual(['db_errors']);

    fireEvent.change(screen.getByTestId('diff-to'), { target: { value: '1' } });
    expect(screen.getByTestId('diff-summary').textContent).toBe('Both sides are the same version.');

    fireEvent.click(screen.getByTestId('diff-close'));
    expect(screen.queryByTestId('policy-diff')).toBeNull();
  });

  it('offers no comparison with a single version', async () => {
    await openDiff(['operator'], versions.slice(2));
    expect(screen.queryByTestId('policy-compare')).toBeNull();
  });
});
