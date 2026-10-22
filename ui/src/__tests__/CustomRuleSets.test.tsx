import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { CustomRuleSets } from '../components/rules/CustomRuleSets';
import { PolicyEditor } from '../components/policy/PolicyEditor';
import { ApiError, PolicySpec, RuleSet, apiClient } from '../api/client';
import { refreshCustomSet, sameFilter, setRuleSet } from '../lib/ruleSets';
import { diffSpecs } from '../lib/policyDiff';
import i18n from '../i18n';

const builtIn: RuleSet = { name: 'bots-scanners', group: 'bot', class: 'malicious', title: { vi: 'Công cụ quét', en: 'Scanners' }, match: { tags: ['scanner'] }, rule_count: 48 };
const custom: RuleSet = { name: 'custom-our-scanners', group: 'custom', custom: true, title: { vi: 'Our scanners', en: 'Our scanners' }, match: { tags: ['scanner'], ids: [913100] }, rule_count: 49, version: 2, etag: 'e2', updated_by: 'example-operator' };

beforeEach(() => {
  vi.restoreAllMocks();
  void i18n.changeLanguage('en');
});

// RS-3c: custom rule sets.
describe('custom rule set helpers', () => {
  it('keep the copy of a custom filter, compare and drop it, and show it in the diff', () => {
    const spec: PolicySpec = { mode: 'MODE_SHADOW', rule_sets: [{ set: 'custom-our-scanners', action: 'POLICY_RULE_ACTION_LOG', match: { tags: ['scanner'] } }] };
    const blocked = setRuleSet(spec, [builtIn, custom], 'custom-our-scanners', 'POLICY_RULE_ACTION_BLOCK');
    expect(blocked.rule_sets).toEqual([{ set: 'custom-our-scanners', action: 'POLICY_RULE_ACTION_BLOCK', match: { tags: ['scanner'] } }]);
    expect(sameFilter({ ids: [2, 1], tags: ['a'] }, { tags: ['a'], ids: [1, 2] })).toBe(true);
    expect(sameFilter(spec.rule_sets![0].match, custom.match)).toBe(false);
    expect(refreshCustomSet(blocked, 'custom-our-scanners').rule_sets).toEqual([{ set: 'custom-our-scanners', action: 'POLICY_RULE_ACTION_BLOCK' }]);
    const rules = diffSpecs(spec, { ...spec, rule_sets: [{ ...spec.rule_sets![0], match: { tags: ['scanner'], ids: [913100] } }] }).find((b) => b.block === 'rules')!;
    expect(rules.fields[0]).toMatchObject({ changed: true, to: 'custom-our-scanners: log [tags=scanner ids=913100]' });
  });
});

describe('custom rule sets on Rules & packs', () => {
  it('creates a set from a built-in one', async () => {
    const create = vi.spyOn(apiClient, 'createCustomRuleSet').mockResolvedValue({ ...custom, description: '', created_by: 'x', created_at: '', updated_at: '' } as never);
    const changed = vi.fn();
    render(<CustomRuleSets sets={[builtIn]} facets={{ sources: ['crs'], attack_types: ['xss'] }} canWrite onChanged={changed} />);
    expect(screen.getByTestId('custom-empty')).toBeInTheDocument();
    fireEvent.click(screen.getByTestId('custom-new'));
    expect(screen.getByTestId('custom-save')).toBeDisabled();
    fireEvent.change(screen.getByTestId('custom-copy'), { target: { value: 'bots-scanners' } });
    expect(screen.getByTestId('custom-tags')).toHaveValue('scanner');
    fireEvent.change(screen.getByTestId('custom-suffix'), { target: { value: 'Our-Scanners' } });
    expect(screen.getByTestId('custom-suffix')).toHaveValue('our-scanners');
    fireEvent.change(screen.getByTestId('custom-ids'), { target: { value: '913100, x' } });
    expect(screen.getByTestId('custom-save')).toBeDisabled();
    fireEvent.change(screen.getByTestId('custom-ids'), { target: { value: '913100 913100' } });
    fireEvent.change(screen.getByTestId('custom-title'), { target: { value: ' Our scanners ' } });
    fireEvent.click(screen.getByTestId('custom-save'));
    await waitFor(() => expect(changed).toHaveBeenCalled());
    expect(create).toHaveBeenCalledWith({ name: 'custom-our-scanners', title: 'Our scanners', description: '', match: { tags: ['scanner'], ids: [913100] } });
  });

  it('edits with the etag read, reports a conflict, deletes after confirming; viewers only read', async () => {
    const update = vi.spyOn(apiClient, 'updateCustomRuleSet').mockRejectedValue(new ApiError('stale', 409));
    const remove = vi.spyOn(apiClient, 'deleteCustomRuleSet').mockResolvedValue(undefined);
    vi.spyOn(window, 'confirm').mockReturnValue(true);
    const changed = vi.fn();
    const { unmount } = render(<CustomRuleSets sets={[builtIn, custom]} canWrite onChanged={changed} />);
    expect(screen.getByTestId('custom-row')).toHaveTextContent('tags=scanner ids=913100');
    fireEvent.click(screen.getByTestId('custom-edit-custom-our-scanners'));
    fireEvent.change(screen.getByTestId('custom-ids'), { target: { value: '' } });
    fireEvent.click(screen.getByTestId('custom-save'));
    expect(await screen.findByRole('alert')).toHaveTextContent('just changed');
    expect(update).toHaveBeenCalledWith('custom-our-scanners', { title: 'Our scanners', description: '', match: { tags: ['scanner'] }, etag: 'e2' });
    fireEvent.click(screen.getByTestId('custom-delete-custom-our-scanners'));
    await waitFor(() => expect(remove).toHaveBeenCalledWith('custom-our-scanners', 'e2'));
    expect(changed).toHaveBeenCalled();
    unmount();
    render(<CustomRuleSets sets={[builtIn, custom]} canWrite={false} onChanged={changed} />);
    expect(screen.queryByTestId('custom-new')).not.toBeInTheDocument();
    expect(screen.queryByTestId('custom-edit-custom-our-scanners')).not.toBeInTheDocument();
  });
});

describe('custom rule sets in the policy editor', () => {
  it('says when the copy is older than the set, takes the current one on request, and keeps a deleted set\'s copy', async () => {
    vi.spyOn(apiClient, 'listRuleSets').mockResolvedValue({ sets: [builtIn, custom], catalog_available: true });
    vi.spyOn(apiClient, 'resolveRuleActions').mockResolvedValue({ rules: [], total: 0, next_cursor: 0, counts: {} });
    const update = vi.spyOn(apiClient, 'updatePolicy').mockResolvedValue({ id: 'resource-api', version: 3 });
    const spec: PolicySpec = { mode: 'MODE_SHADOW', rule_sets: [
      { set: 'custom-our-scanners', action: 'POLICY_RULE_ACTION_BLOCK', match: { tags: ['scanner'] } },
      { set: 'custom-gone', action: 'POLICY_RULE_ACTION_LOG', match: { ids: [1] } },
    ] };
    render(<PolicyEditor policy={{ id: 'resource-api', name: 'example-api', etag: 'e1', spec }} onSaved={vi.fn()} onCancel={vi.fn()} />);
    expect(await screen.findByTestId('rulesets-group-custom')).toHaveTextContent('Our scanners');
    expect(screen.getByTestId('ruleset-stale-custom-our-scanners')).toHaveTextContent('changed (v2)');
    expect(screen.getByTestId('ruleset-unknown')).toHaveTextContent('custom-gone was deleted; the policy keeps the filter it copied (ids=1)');
    fireEvent.click(screen.getByTestId('ruleset-refresh-custom-our-scanners'));
    expect(screen.queryByTestId('ruleset-stale-custom-our-scanners')).not.toBeInTheDocument();
    fireEvent.click(screen.getByTestId('editor-save'));
    await waitFor(() => expect(update).toHaveBeenCalled());
    expect(update.mock.calls[0][1].rule_sets).toEqual([{ set: 'custom-our-scanners', action: 'POLICY_RULE_ACTION_BLOCK' }, { set: 'custom-gone', action: 'POLICY_RULE_ACTION_LOG', match: { ids: [1] } }]);
  });
});
