import { beforeEach, describe, expect, it, vi } from 'vitest';
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { PolicyEditor } from '../components/policy/PolicyEditor';
import { apiClient, PolicySpec, RuleSet } from '../api/client';
import { advancedSpec, mergeYamlSpec, normalizeSpec, specToYaml } from '../lib/policyYaml';
import { draftOf, ruleActionsValid, setOverride, setRuleSet } from '../lib/ruleSets';
import i18n from '../i18n';

const catalog: RuleSet[] = [
  { name: 'attack-sqli', group: 'attack', title: { vi: 'SQL injection', en: 'SQL injection' }, match: { attack_types: ['sql-injection'] }, rule_count: 2 },
  { name: 'bots-scanners', group: 'bot', class: 'malicious', title: { vi: 'Công cụ quét', en: 'Scanners' }, match: { tags: ['scanner'] }, rule_count: 1, matches_24h: 1234 },
  { name: 'bots-trusted', group: 'bot', class: 'trusted', title: { vi: 'Bot tin cậy', en: 'Trusted bots' }, match: { tags: ['search-engine'] }, rule_count: 0 },
];

beforeEach(() => {
  vi.restoreAllMocks();
  void i18n.changeLanguage('en');
});

// RS-4: rule sets and overrides of a policy.
describe('rule set helpers', () => {
  it('keep the catalog order, drop the default action, sort overrides', () => {
    let spec: PolicySpec = { mode: 'MODE_SHADOW' };
    spec = setRuleSet(spec, catalog, 'bots-trusted', 'POLICY_RULE_ACTION_LOG');
    spec = setRuleSet(spec, catalog, 'attack-sqli', 'POLICY_RULE_ACTION_BLOCK');
    expect(spec.rule_sets).toEqual([{ set: 'attack-sqli', action: 'POLICY_RULE_ACTION_BLOCK' }, { set: 'bots-trusted', action: 'POLICY_RULE_ACTION_LOG' }]);
    spec = setRuleSet(spec, catalog, 'bots-trusted', 'POLICY_RULE_ACTION_UNSPECIFIED');
    expect(spec.rule_sets![1]).toEqual({ set: 'bots-trusted' });
    expect(setRuleSet(setRuleSet(spec, catalog, 'attack-sqli', undefined), catalog, 'bots-trusted', undefined).rule_sets).toBeUndefined();
    // a set the catalog does not know keeps its place at the end
    const odd = setRuleSet({ mode: 'MODE_SHADOW', rule_sets: [{ set: 'custom-x', action: 'POLICY_RULE_ACTION_OFF' }] }, catalog, 'attack-sqli', 'POLICY_RULE_ACTION_LOG');
    expect(odd.rule_sets!.map((r) => r.set)).toEqual(['attack-sqli', 'custom-x']);

    spec = setOverride(spec, 942100, { action: 'POLICY_RULE_ACTION_OFF', reason: 'FP' });
    spec = setOverride(spec, 913100, { action: 'POLICY_RULE_ACTION_LOG' });
    expect(spec.rule_overrides!.map((o) => o.rule)).toEqual([913100, 942100]);
    expect(ruleActionsValid(spec)).toBe(false); // 913100 has no reason
    spec = setOverride(spec, 913100, { reason: 'watching' });
    expect(ruleActionsValid(spec)).toBe(true);
    expect(draftOf(spec, [1, 2])).toEqual({
      crs_paranoia_shadow: 2,
      rule_sets: [{ set: 'attack-sqli', action: 'block' }, { set: 'bots-trusted', action: 'default' }],
      rule_overrides: [{ rule: 913100, action: 'log', reason: 'watching' }, { rule: 942100, action: 'off', reason: 'FP' }],
    });
    expect(setOverride(spec, 913100, undefined).rule_overrides!.map((o) => o.rule)).toEqual([942100]);
  });

  it('stay out of the YAML view and the advanced block, and survive YAML edits', () => {
    const spec: PolicySpec = { mode: 'MODE_SHADOW', rule_sets: [{ set: 'bots-scanners', action: 'POLICY_RULE_ACTION_BLOCK' }], rule_overrides: [{ rule: 1, action: 'POLICY_RULE_ACTION_OFF', reason: 'x' }] };
    expect(specToYaml(spec)).toBe('mode: shadow\n');
    expect(advancedSpec(spec)).toEqual({});
    expect(mergeYamlSpec(spec, { mode: 'MODE_ENFORCE' })).toMatchObject({ rule_sets: spec.rule_sets, rule_overrides: spec.rule_overrides });
    expect(normalizeSpec({ mode: 'MODE_SHADOW', rule_sets: [], rule_overrides: [] })).toEqual({ mode: 'MODE_SHADOW' });
    // the API may send the default action explicitly
    expect(normalizeSpec({ mode: 'MODE_SHADOW', rule_sets: [{ set: 'bots-scanners', action: 'POLICY_RULE_ACTION_UNSPECIFIED' }] }).rule_sets).toEqual([{ set: 'bots-scanners' }]);
  });
});

describe('rule sets in the policy editor', () => {
  const mocks = () => {
    vi.spyOn(apiClient, 'listRuleSets').mockResolvedValue({ sets: catalog, catalog_available: true });
    const resolve = vi.spyOn(apiClient, 'resolveRuleActions').mockResolvedValue({
      rules: [{ id: 500901, name: 'Example scanner', pack: 'signature', digest: 'd', action: 'block', own: 'log', source: 'set', set: 'bots-scanners' }],
      total: 1, next_cursor: 0, counts: { block: 1, log: 3, off: 0, score: 2 },
    });
    const rules = vi.spyOn(apiClient, 'listRuleSetRules').mockResolvedValue({
      set: 'attack-sqli', total: 2, next_cursor: 0,
      rules: [{ id: 942100, name: 'SQL injection via libinjection', pack: 'core', digest: 'a', severity: 'critical' }, { id: 942200, name: 'SQL injection level 2', pack: 'core', digest: 'b' }],
    });
    return { resolve, rules };
  };

  it('turn a set on, give it an action, override a rule of it with a reason, and save', async () => {
    const { resolve, rules } = mocks();
    const update = vi.spyOn(apiClient, 'updatePolicy').mockResolvedValue({ id: 'resource-api', version: 2 });
    render(<PolicyEditor policy={{ id: 'resource-api', name: 'example-api', etag: 'e1', spec: { mode: 'MODE_SHADOW' } }} onSaved={vi.fn()} onCancel={vi.fn()} />);
    const bots = await screen.findByTestId('rulesets-group-bot');
    expect(within(bots).getByText('Scanners')).toBeInTheDocument();
    expect(screen.getByTestId('ruleset-count-attack-sqli')).toHaveTextContent('2 rules');
    expect(screen.getByTestId('ruleset-matches-bots-scanners')).toHaveTextContent('1234 matches in 24 h');
    expect(screen.queryByTestId('ruleset-matches-attack-sqli')).not.toBeInTheDocument();
    expect(apiClient.listRuleSets).toHaveBeenCalledWith(expect.anything(), 'example-api');
    // no rules to list: the button is off
    expect(screen.getByTestId('ruleset-view-bots-trusted')).toBeDisabled();
    expect(screen.getByTestId('ruleset-action-bots-scanners')).toBeDisabled();

    fireEvent.click(screen.getByTestId('ruleset-on-bots-scanners'));
    fireEvent.change(screen.getByTestId('ruleset-action-bots-scanners'), { target: { value: 'POLICY_RULE_ACTION_BLOCK' } });
    await waitFor(() => expect(resolve).toHaveBeenLastCalledWith({ rule_sets: [{ set: 'bots-scanners', action: 'block' }] }, { changed: true }, expect.anything()), { timeout: 2000 });
    expect(await screen.findByTestId('rulesets-impact')).toHaveTextContent('1 rules block alone');
    fireEvent.click(screen.getByTestId('rulesets-changed'));
    expect(screen.getByTestId('rulesets-changed-list')).toHaveTextContent('log → block');

    fireEvent.click(screen.getByTestId('ruleset-view-attack-sqli'));
    await waitFor(() => expect(rules).toHaveBeenCalledWith('attack-sqli', '', 0, expect.anything()), { timeout: 2000 });
    fireEvent.change(await screen.findByTestId('ruleset-rule-action-942100'), { target: { value: 'POLICY_RULE_ACTION_LOG' } });
    // an override needs its reason before saving
    expect(screen.getByTestId('editor-save')).toBeDisabled();
    fireEvent.change(screen.getByTestId('ruleset-rule-reason-942100'), { target: { value: 'FP on /search' } });
    expect(screen.getByTestId('editor-save')).toBeEnabled();
    expect(screen.getByTestId('rulesets-tab-overrides')).toHaveTextContent('Overrides (1)');

    fireEvent.click(screen.getByTestId('editor-save'));
    await waitFor(() => expect(update).toHaveBeenCalled());
    expect(update.mock.calls[0][1]).toEqual({
      mode: 'MODE_SHADOW',
      rule_sets: [{ set: 'bots-scanners', action: 'POLICY_RULE_ACTION_BLOCK' }],
      rule_overrides: [{ rule: 942100, action: 'POLICY_RULE_ACTION_LOG', reason: 'FP on /search' }],
    });
  });

  it('list, edit, add and remove overrides', async () => {
    mocks();
    const spec: PolicySpec = { mode: 'MODE_SHADOW', rule_overrides: [{ rule: 942100, action: 'POLICY_RULE_ACTION_OFF', reason: 'noisy' }] };
    render(<PolicyEditor policy={{ id: 'resource-api', name: 'example-api', etag: 'e1', spec }} onSaved={vi.fn()} onCancel={vi.fn()} />);
    await screen.findByTestId('rulesets-group-bot');
    fireEvent.click(screen.getByTestId('rulesets-tab-overrides'));
    expect(screen.getAllByTestId('override-row')).toHaveLength(1);
    expect(screen.getByTestId('override-action-942100')).toHaveValue('POLICY_RULE_ACTION_OFF');
    // a duplicate or a bad ID cannot be added; nor without a reason
    fireEvent.change(screen.getByTestId('override-new-rule'), { target: { value: '942100' } });
    fireEvent.change(screen.getByTestId('override-new-reason'), { target: { value: 'again' } });
    expect(screen.getByTestId('override-add')).toBeDisabled();
    fireEvent.change(screen.getByTestId('override-new-rule'), { target: { value: '0' } });
    expect(screen.getByTestId('override-add')).toBeDisabled();
    fireEvent.change(screen.getByTestId('override-new-rule'), { target: { value: '913100' } });
    fireEvent.change(screen.getByTestId('override-new-action'), { target: { value: 'POLICY_RULE_ACTION_LOG' } });
    fireEvent.change(screen.getByTestId('override-new-reason'), { target: { value: '   ' } });
    expect(screen.getByTestId('override-add')).toBeDisabled();
    fireEvent.change(screen.getByTestId('override-new-reason'), { target: { value: 'scanner of ours' } });
    fireEvent.click(screen.getByTestId('override-add'));
    expect(screen.getAllByTestId('override-row').map((r) => r.textContent)).toEqual([expect.stringContaining('913100'), expect.stringContaining('942100')]);
    fireEvent.click(screen.getByTestId('override-remove-942100'));
    expect(screen.getAllByTestId('override-row')).toHaveLength(1);
    expect(screen.getByTestId('editor-save')).toBeEnabled();
  });

  it('works without a configured catalog', async () => {
    vi.spyOn(apiClient, 'listRuleSets').mockResolvedValue({ sets: catalog.map((s) => ({ ...s, rule_count: undefined })), catalog_available: false });
    vi.spyOn(apiClient, 'resolveRuleActions').mockRejectedValue(new Error('503'));
    render(<PolicyEditor policy={{ id: 'resource-api', name: 'example-api', etag: 'e1', spec: { mode: 'MODE_SHADOW' } }} onSaved={vi.fn()} onCancel={vi.fn()} />);
    expect(await screen.findByTestId('rulesets-no-catalog')).toBeInTheDocument();
    expect(screen.getByTestId('ruleset-count-attack-sqli')).toHaveTextContent('—');
    expect(screen.getByTestId('ruleset-view-attack-sqli')).toBeDisabled();
    await act(async () => { await new Promise((r) => setTimeout(r, 500)); });
    expect(screen.getByTestId('rulesets-impact-unavailable')).toBeInTheDocument();
  });
});
