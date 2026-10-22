import { beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { RuleOverrideDraft } from '../components/events/RuleOverrideDraft';
import { ApiError, Event, apiClient } from '../api/client';
import { StaticAuthProvider, UserRole } from '../context/AuthContext';
import { diffSpecs } from '../lib/policyDiff';
import i18n from '../i18n';

const event: Event = {
  block_id: 'STR-8F3K-Q2VD-7XNM-A1PC', timestamp: '2026-10-23T00:00:00Z', node_id: 'example-node', connector_type: 'nginx', policy_id: 'example-api', policy_version: 3, client_ip: '198.51.100.42',
  http_method: 'GET', http_host: 'api.example.test', http_path: '/search', action: 'block', status_code: 403,
  violations: [
    { rule_id: 942100, layer: 'sqli', field: 'ARGS:q', snippet: 'x' },
    { rule_id: 942100, layer: 'sqli', field: 'ARGS:r', snippet: 'y' },
    { rule_id: 920350, layer: 'protocol', field: 'REQUEST_HEADERS:Host', snippet: 'z' },
    { rule_id: 190000, layer: 'geo', field: '', snippet: '' },
  ],
};
const rules = { '942100': { name: 'SQL injection via libinjection', layer: 'managed' }, '920350': { name: 'Host is an IP', layer: 'managed' }, '190000': { name: 'geo', layer: 'policy' } };
const policy = { id: 'resource-1', name: 'example-api', etag: 'v3', version: 3, spec: { mode: 'MODE_ENFORCE' as const, rule_overrides: [{ rule: 920350, action: 'POLICY_RULE_ACTION_OFF' as const, reason: 'internal hosts' }] } };

beforeEach(() => {
  vi.restoreAllMocks();
  void i18n.changeLanguage('en');
  vi.spyOn(apiClient, 'listPolicies').mockResolvedValue([policy]);
});
const setup = (roles: UserRole[] = ['operator'], ev = event) => render(<StaticAuthProvider roles={roles}><RuleOverrideDraft event={ev} rules={rules} /></StaticAuthProvider>);

// RS-4b: override a rule of an event for the whole policy.
describe('rule override from an event', () => {
  it('is for policy writers, on events with detection rules', () => {
    for (const role of ['viewer', 'approver'] as UserRole[]) {
      setup([role]); expect(screen.queryByTestId('override-open')).not.toBeInTheDocument(); cleanup();
    }
    setup(['operator'], { ...event, violations: [{ rule_id: 190000, layer: 'geo', field: '', snippet: '' }] });
    expect(screen.queryByTestId('override-open')).not.toBeInTheDocument();
  });

  it('saves a new draft version with the override, keeping the others', async () => {
    const update = vi.spyOn(apiClient, 'updatePolicy').mockResolvedValue({ id: 'resource-1', version: 4 });
    setup();
    fireEvent.click(screen.getByTestId('override-open'));
    const select = screen.getByTestId('override-rule');
    // each detection rule once; not the geo rule
    expect([...select.querySelectorAll('option')].map((o) => o.value)).toEqual(['942100', '920350']);
    await waitFor(() => expect(screen.queryByText('Reading the current policy…')).not.toBeInTheDocument());
    expect(screen.getByTestId('override-save')).toBeDisabled();
    fireEvent.change(screen.getByTestId('override-reason'), { target: { value: '  FP on /search  ' } });
    fireEvent.click(screen.getByTestId('override-save'));
    expect(await screen.findByTestId('override-created')).toHaveTextContent('draft version 4');
    expect(update).toHaveBeenCalledWith('resource-1', {
      mode: 'MODE_ENFORCE',
      rule_overrides: [{ rule: 920350, action: 'POLICY_RULE_ACTION_OFF', reason: 'internal hosts' }, { rule: 942100, action: 'POLICY_RULE_ACTION_LOG', reason: 'FP on /search' }],
    }, 'v3');
  });

  it('shows an existing override it replaces, and a conflict', async () => {
    vi.spyOn(apiClient, 'updatePolicy').mockRejectedValue(new ApiError('stale', 409));
    setup();
    fireEvent.click(screen.getByTestId('override-open'));
    fireEvent.change(screen.getByTestId('override-rule'), { target: { value: '920350' } });
    expect(await screen.findByTestId('override-current')).toHaveTextContent('Off (internal hosts)');
    fireEvent.change(screen.getByTestId('override-action'), { target: { value: 'POLICY_RULE_ACTION_LOG' } });
    fireEvent.change(screen.getByTestId('override-reason'), { target: { value: 'watch it' } });
    fireEvent.click(screen.getByTestId('override-save'));
    expect(await screen.findByRole('alert')).toHaveTextContent('just changed');
  });
});

describe('rule sets and overrides in the policy diff', () => {
  it('list each set and override, with what was added and removed', () => {
    const a = { mode: 'MODE_SHADOW' as const, rule_sets: [{ set: 'bots-scanners', action: 'POLICY_RULE_ACTION_LOG' as const }] };
    const b = { mode: 'MODE_SHADOW' as const, rule_sets: [{ set: 'bots-scanners', action: 'POLICY_RULE_ACTION_BLOCK' as const }],
      rule_overrides: [{ rule: 942100, action: 'POLICY_RULE_ACTION_OFF' as const, reason: 'FP' }] };
    const rules = diffSpecs(a, b).find((x) => x.block === 'rules')!;
    expect(rules.changed).toBe(2);
    expect(rules.fields[0]).toMatchObject({ key: 'rule_sets', from: 'bots-scanners: log', to: 'bots-scanners: block', added: ['bots-scanners: block'], removed: ['bots-scanners: log'] });
    expect(rules.fields[1]).toMatchObject({ key: 'rule_overrides', from: '—', to: '942100: off (FP)', added: ['942100: off (FP)'], removed: [] });
    // no block when neither version has any
    expect(diffSpecs({ mode: 'MODE_SHADOW' }, { mode: 'MODE_ENFORCE' }).find((x) => x.block === 'rules')).toBeUndefined();
  });
});
