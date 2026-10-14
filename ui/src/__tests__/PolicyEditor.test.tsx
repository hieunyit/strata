// W11-F-01: policy editor, part 1. Form and YAML side by side, kept in sync
// both ways; saving makes a draft version with the etag the policy was read
// with.
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor, cleanup } from '@testing-library/react';
import { StaticAuthProvider } from '../context/AuthContext';
import { PoliciesPage } from '../pages/PoliciesPage';
import { apiClient, ApiError, Policy } from '../api/client';
import { specToYaml, yamlToSpec, normalizeSpec } from '../lib/policyYaml';
import i18n from '../i18n';

beforeEach(() => {
  vi.restoreAllMocks();
  vi.spyOn(apiClient, 'getVersion').mockResolvedValue({ version: 'test', commit: '', api_version: 'v1' });
  void i18n.changeLanguage('en');
});

describe('policy YAML', () => {
  it('writes the canonical text and reads it back', () => {
    const spec = {
      mode: 'MODE_ENFORCE' as const,
      oversize: 'OVERSIZE_BLOCK' as const,
      response: { allowed_codes_check: true, data_guard: ['cccd', 'jwt'] },
    };
    const y = specToYaml(spec);
    expect(y).toBe('mode: enforce\noversize: block\nresponse:\n  allowed_codes_check: true\n  data_guard: [cccd, jwt]\n');
    expect(yamlToSpec(y).spec).toEqual(spec);
    expect(specToYaml({ mode: 'MODE_SHADOW' })).toBe('mode: shadow\n');
  });

  it('reads block lists, quotes and comments', () => {
    const r = yamlToSpec('# pilot\nmode: "shadow"\nresponse:\n  db_errors: true  # SQL errors\n  data_guard:\n    - jwt\n');
    expect(r.spec).toEqual({ mode: 'MODE_SHADOW', response: { db_errors: true, data_guard: ['jwt'] } });
  });

  it('refuses what the compiler schema refuses, with the line', () => {
    const cases: [string, number, string][] = [
      ['mode: block\n', 1, 'mode'],
      ['mode: shadow\noversize: drop\n', 2, 'oversize'],
      ['mode: shadow\nmode: enforce\n', 2, 'twice'],
      ['mode: shadow\ncanary: 5\n', 2, 'unknown'],
      ['mode: shadow\nresponse:\n  data_guard: [ssn]\n', 3, 'guard'],
      ['mode: shadow\nresponse:\n  data_guard: [jwt, jwt]\n', 3, 'guardTwice'],
      ['mode: shadow\nresponse:\n  db_errors: yes\n', 3, 'bool'],
      ['mode: shadow\nresponse:\n  block: true\n', 3, 'unknown'],
      ['oversize: pass\n', 1, 'modeRequired'],
      ['mode: shadow\n\toversize: pass\n', 2, 'tab'],
      ['  mode: shadow\n', 1, 'indent'],
    ];
    for (const [text, line, code] of cases) {
      expect(yamlToSpec(text).error, text).toMatchObject({ line, code });
    }
  });

  it('normalizes what the API may send', () => {
    expect(normalizeSpec({ mode: 'MODE_UNSPECIFIED', oversize: 'OVERSIZE_UNSPECIFIED', response: {} })).toEqual({ mode: 'MODE_SHADOW' });
  });
});

const policy: Policy = {
  id: 'example-api',
  name: 'example-api',
  version: 3,
  etag: 'etag-3',
  spec: { mode: 'MODE_SHADOW', oversize: 'OVERSIZE_PASS' },
};

function setup(roles: ('viewer' | 'operator' | 'approver' | 'admin')[] = ['operator']) {
  vi.spyOn(apiClient, 'listPolicies').mockResolvedValue([policy]);
  vi.spyOn(apiClient, 'listPolicyVersions').mockResolvedValue([
    { policy_id: 'example-api', version: 3, spec: policy.spec, state: 'DEPLOYED' },
  ]);
  render(<StaticAuthProvider roles={roles}><PoliciesPage /></StaticAuthProvider>);
}

async function openEditor() {
  fireEvent.click(await screen.findByTestId('policy-row'));
  fireEvent.click(await screen.findByTestId('policy-edit'));
  return screen.findByTestId('policy-editor');
}

const yamlBox = () => screen.getByTestId('editor-yaml') as HTMLTextAreaElement;

describe('policy editor (W11-F-01)', () => {
  it('only operators and admins see the editor', async () => {
    for (const [roles, shown] of [[['viewer'], false], [['approver'], false], [['admin'], true]] as const) {
      setup([...roles]);
      fireEvent.click(await screen.findByTestId('policy-row'));
      await screen.findByTestId('policy-versions');
      expect(!!screen.queryByTestId('policy-edit'), roles[0]).toBe(shown);
      cleanup();
    }
  });

  it('a form edit rewrites the YAML', async () => {
    setup();
    await openEditor();
    expect(yamlBox().value).toBe('mode: shadow\noversize: pass\n');
    fireEvent.click(screen.getByTestId('editor-mode-MODE_ENFORCE'));
    fireEvent.change(screen.getByTestId('editor-oversize'), { target: { value: 'OVERSIZE_BLOCK' } });
    fireEvent.click(screen.getByTestId('editor-guard-jwt'));
    expect(yamlBox().value).toBe('mode: enforce\noversize: block\nresponse:\n  data_guard: [jwt]\n');
  });

  it('a YAML edit updates the form; a broken YAML keeps the form and blocks saving', async () => {
    setup();
    await openEditor();
    const save = screen.getByTestId('editor-save');
    expect(save).toBeDisabled(); // nothing changed yet
    fireEvent.change(yamlBox(), { target: { value: 'mode: enforce\nresponse:\n  db_errors: true\n' } });
    expect(screen.getByTestId('editor-mode-MODE_ENFORCE')).toBeChecked();
    expect(screen.getByTestId('editor-db-errors')).toBeChecked();
    expect(screen.getByTestId('editor-oversize')).toHaveValue('OVERSIZE_UNSPECIFIED');
    expect(save).toBeEnabled();

    fireEvent.change(yamlBox(), { target: { value: 'mode: enforce\nresponse:\n  db_errors: maybe\n' } });
    expect(screen.getByTestId('editor-yaml-error')).toHaveTextContent('Line 3: expected true or false, got "maybe"');
    expect(screen.getByTestId('editor-db-errors')).toBeChecked(); // last valid spec
    expect(save).toBeDisabled();

    // back to valid: the form follows again
    fireEvent.change(yamlBox(), { target: { value: 'mode: shadow\n' } });
    expect(screen.queryByTestId('editor-yaml-error')).toBeNull();
    expect(screen.getByTestId('editor-mode-MODE_SHADOW')).toBeChecked();
  });

  it('saves a draft version with the etag it was read with', async () => {
    setup();
    const update = vi.spyOn(apiClient, 'updatePolicy').mockResolvedValue({ ...policy, version: 4, etag: 'etag-4', spec: { mode: 'MODE_ENFORCE' } });
    await openEditor();
    fireEvent.click(screen.getByTestId('editor-mode-MODE_ENFORCE'));
    vi.spyOn(apiClient, 'listPolicyVersions').mockResolvedValue([
      { policy_id: 'example-api', version: 4, spec: { mode: 'MODE_ENFORCE' }, state: 'DRAFT' },
      { policy_id: 'example-api', version: 3, spec: policy.spec, state: 'DEPLOYED' },
    ]);
    fireEvent.click(screen.getByTestId('editor-save'));
    await waitFor(() => expect(update).toHaveBeenCalledWith('example-api', { mode: 'MODE_ENFORCE', oversize: 'OVERSIZE_PASS' }, 'etag-3'));
    expect(await screen.findByTestId('editor-saved')).toHaveTextContent('Saved as draft version 4.');
    expect(screen.queryByTestId('policy-editor')).toBeNull();
    const states = await screen.findAllByTestId('policy-version-state');
    expect(states.map((s) => s.textContent)).toEqual(['draft', 'deployed']);
  });

  it('a stale etag says someone else saved', async () => {
    setup();
    vi.spyOn(apiClient, 'updatePolicy').mockRejectedValue(new ApiError('etag mismatch', 409));
    await openEditor();
    fireEvent.click(screen.getByTestId('editor-mode-MODE_ENFORCE'));
    fireEvent.click(screen.getByTestId('editor-save'));
    expect(await screen.findByTestId('editor-save-error')).toHaveTextContent('Someone saved this policy in the meantime');
    expect(screen.getByTestId('policy-editor')).toBeInTheDocument();
  });

  it('shows the errors in Vietnamese too', async () => {
    void i18n.changeLanguage('vi');
    setup();
    await openEditor();
    fireEvent.change(yamlBox(), { target: { value: 'mode: block\n' } });
    expect(screen.getByTestId('editor-yaml-error')).toHaveTextContent('Dòng 1: mode là shadow hoặc enforce');
  });
});
