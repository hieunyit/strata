import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { PolicyEditor } from '../components/policy/PolicyEditor';
import { apiClient, PolicySpec } from '../api/client';
import { normalizeSpec } from '../lib/policyYaml';
import { diffSpecs } from '../lib/policyDiff';
import i18n from '../i18n';

const exception = { id: 'exc-0123456789abcdef0123456789abcdef', rule_id: 700011,
  method: 'GET', host: 'api.example.test', path: '/search', field: 'ARGS:Name',
  expires_unix_ms: '4000000000000', reason: 'legitimate query' };
const spec: PolicySpec = { mode: 'MODE_SHADOW', auto_staging: { enabled: false,
  rule_ids: [942100], window_seconds: 300, min_matches: 100, min_reports: 5, fp_threshold_bps: 500 }, exceptions: [exception],
  privacy: { sensitive_fields: ['X-Customer-Id'], identity: 'hmac' }, max_args: 200,
  max_snippet_size: 2048, fail_on_findings: 'FAIL_ON_FINDINGS_BLOCK', response: { data_guard: ['pan'] } };

beforeEach(() => { vi.restoreAllMocks(); void i18n.changeLanguage('en'); });

describe('policy settings outside the basic form', () => {
  it('normalization keeps exceptions, privacy, limits and PAN', () => {
    expect(normalizeSpec(spec)).toEqual(spec);
  });

  it.each(['form', 'yaml'])('a %s edit preserves the other security settings on save', async (mode) => {
    const update = vi.spyOn(apiClient, 'updatePolicy').mockResolvedValue({ id: 'resource-api', version: 3 });
    render(<PolicyEditor policy={{ id: 'resource-api', name: 'example-api', etag: 'e2', spec }} onSaved={vi.fn()} onCancel={vi.fn()} />);
    if (mode === 'form') fireEvent.click(screen.getByTestId('editor-mode-MODE_ENFORCE'));
    else fireEvent.change(screen.getByTestId('editor-yaml'), { target: { value: 'mode: enforce\nresponse:\n  data_guard: [pan]\n' } });
    fireEvent.click(screen.getByTestId('editor-save'));
    await waitFor(() => expect(update).toHaveBeenCalledWith('resource-api', { ...spec, mode: 'MODE_ENFORCE' }, 'e2'));
    expect(screen.getByTestId('editor-advanced')).toHaveTextContent('ARGS:Name');
    expect(screen.getByTestId('editor-advanced')).toHaveTextContent('X-Customer-Id');
  });

  it('review diff exposes exception scope, expiry and removal', () => {
    const d = diffSpecs({ mode: 'MODE_ENFORCE' }, { ...spec, mode: 'MODE_ENFORCE' });
    const advanced = d.find((b) => b.block === 'advanced');
    expect(advanced?.changed).toBe(1);
    expect(advanced?.fields[0].to).toContain('ARGS:Name');
    expect(advanced?.fields[0].to).toContain('4000000000000');
    expect(advanced?.fields[0].to).toContain('/search');
    expect(diffSpecs(spec, { ...spec, exceptions: [] }).find((b) => b.block === 'advanced')?.changed).toBe(1);
  });
  it('preserves opt-in metadata and exposes threshold changes to approval diff', () => {
    const a: PolicySpec = { mode: 'MODE_ENFORCE', auto_staging: { enabled: true,
      rule_ids: [942100], window_seconds: 300, min_matches: 100, min_reports: 5, fp_threshold_bps: 500 } };
    expect(normalizeSpec(a)).toEqual(a);
    const d = diffSpecs(a, { ...a, auto_staging: { ...a.auto_staging, enabled: false } });
    expect(d.find((b) => b.block === 'advanced')?.changed).toBe(1);
    expect(d.find((b) => b.block === 'advanced')?.fields[0].from).toContain('942100');
  });

});
