import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { StaticAuthProvider } from '../context/AuthContext';
import { PolicyEditor } from '../components/policy/PolicyEditor';
import { MapPage } from '../pages/MapPage';
import { apiClient, ApiError, PolicySpec } from '../api/client';
import { geoRuleSummary, normalizeGeoRule, parseAsns, parseCountries, withGeoRule } from '../lib/geoRules';
import { mergeYamlSpec, normalizeSpec, specToYaml } from '../lib/policyYaml';
import { diffSpecs } from '../lib/policyDiff';
import i18n from '../i18n';

beforeEach(() => {
  vi.restoreAllMocks();
  void i18n.changeLanguage('en');
});

// W19-G2-01 / W19-F-01: geo rules of a policy.
describe('geo rule helpers', () => {
  it('parse, normalize and summarize', () => {
    expect(parseCountries('vn, US;cn  xx1 USA')).toEqual({ values: ['VN', 'US', 'CN'], bad: ['xx1', 'USA'] });
    expect(parseAsns('7552 AS15169 as0 0 4294967296 abc')).toEqual({ values: [7552, 15169], bad: ['as0', '0', '4294967296', 'abc'] });
    expect(normalizeGeoRule({ countries: ['VN', 'CN', 'VN'], asns: [9, 3], action: 'ACTION_UNSPECIFIED', id: 0 })).toEqual({
      countries: ['CN', 'VN'],
      asns: [3, 9],
      action: 'ACTION_BLOCK',
    });
    expect(geoRuleSummary({ id: 190001, countries: ['VN'], asns: [7552], not: true, action: 'ACTION_LOG' })).toBe('190001 log outside VN, AS7552');
  });

  it('add a rule for a country or ASN once', () => {
    const base: PolicySpec = { mode: 'MODE_ENFORCE', geo_rules: [{ id: 190000, countries: ['US'], action: 'ACTION_BLOCK' }] };
    const vn = withGeoRule(base, { country: 'VN' }, 'ACTION_BLOCK');
    expect(vn.added).toBe(true);
    expect(vn.spec.geo_rules).toEqual([...base.geo_rules!, { countries: ['VN'], action: 'ACTION_BLOCK' }]);
    expect(withGeoRule(base, { country: 'US' }, 'ACTION_BLOCK').added).toBe(false);
    expect(withGeoRule(base, { country: 'US' }, 'ACTION_LOG').added).toBe(true);
    expect(withGeoRule(base, { asn: 7552 }, 'ACTION_LOG').spec.geo_rules![1]).toEqual({ asns: [7552], action: 'ACTION_LOG' });
    const full: PolicySpec = { mode: 'MODE_SHADOW', geo_rules: Array.from({ length: 16 }, (_, i) => ({ id: 190000 + i, countries: ['US'], action: 'ACTION_LOG' as const })) };
    expect(() => withGeoRule(full, { country: 'VN' }, 'ACTION_BLOCK')).toThrow();
  });

  it('stay out of the YAML view, are kept on YAML edits, and show in the diff', () => {
    const spec: PolicySpec = { mode: 'MODE_SHADOW', geo_rules: [{ id: 190000, countries: ['VN'], action: 'ACTION_BLOCK' }] };
    expect(specToYaml(spec)).toBe('mode: shadow\n');
    expect(mergeYamlSpec(spec, { mode: 'MODE_ENFORCE' }).geo_rules).toEqual(spec.geo_rules);
    const general = diffSpecs({ mode: 'MODE_SHADOW' }, spec).find((b) => b.block === 'general')!;
    expect(general.fields.find((f) => f.key === 'geo_rules')).toMatchObject({ from: '—', to: '190000 block VN', changed: true });
    expect(diffSpecs({ mode: 'MODE_SHADOW' }, spec).find((b) => b.block === 'advanced')).toBeUndefined();
    expect(normalizeSpec({ mode: 'MODE_SHADOW', geo_rules: [] })).toEqual({ mode: 'MODE_SHADOW' });
  });
});

describe('geo rules in the policy editor', () => {
  it('add, type, refuse bad entries, and save', async () => {
    const update = vi.spyOn(apiClient, 'updatePolicy').mockResolvedValue({ id: 'resource-api', version: 2 });
    render(
      <PolicyEditor
        policy={{ id: 'resource-api', name: 'example-api', etag: 'e1', spec: { mode: 'MODE_SHADOW', geo_rules: [{ id: 190005, asns: [64500], action: 'ACTION_LOG' }] } }}
        onSaved={vi.fn()}
        onCancel={vi.fn()}
      />,
    );
    const box = screen.getByTestId('editor-geo-rules');
    expect(within(box).getByText('#190005')).toBeInTheDocument();
    expect(within(box).getByTestId('editor-geo-asns')).toHaveValue('64500');
    fireEvent.click(within(box).getByTestId('editor-geo-add'));
    // an empty rule cannot be saved
    expect(screen.getByTestId('editor-save')).toBeDisabled();
    const rows = within(box).getAllByTestId('editor-geo-rule');
    fireEvent.change(within(rows[1]).getByTestId('editor-geo-countries'), { target: { value: 'vn, cn, zz9' } });
    expect(within(rows[1]).getByTestId('editor-geo-error')).toHaveTextContent('zz9');
    fireEvent.change(within(rows[1]).getByTestId('editor-geo-countries'), { target: { value: 'vn, cn' } });
    fireEvent.click(within(rows[1]).getByTestId('editor-geo-not'));
    expect(screen.getByTestId('editor-save')).not.toBeDisabled();
    fireEvent.click(screen.getByTestId('editor-save'));
    await waitFor(() =>
      expect(update).toHaveBeenCalledWith(
        'resource-api',
        {
          mode: 'MODE_SHADOW',
          geo_rules: [
            { id: 190005, asns: [64500], action: 'ACTION_LOG' },
            { countries: ['CN', 'VN'], not: true, action: 'ACTION_BLOCK' },
          ],
        },
        'e1',
      ),
    );
  });
});

describe('map: create a geo rule (W19-F-01)', () => {
  const policy = { id: 'resource-api', name: 'example-api', etag: 'e7', spec: { mode: 'MODE_ENFORCE' as const } };
  const stats = () => {
    vi.spyOn(apiClient, 'getVersion').mockResolvedValue({ version: 'test', commit: '', api_version: 'v1' });
    vi.spyOn(apiClient, 'getGeo').mockImplementation(async (groupBy, from, to) => ({ from, to, group_by: groupBy, rows: [], approximate: true }));
    vi.spyOn(apiClient, 'getTimeline').mockImplementation(async (from, to) => ({ from, to, step: '1h0m0s', approximate: true, buckets: [] }));
    vi.spyOn(apiClient, 'watchGeo').mockImplementation(async () => {});
    vi.spyOn(apiClient, 'listPolicies').mockResolvedValue([policy]);
  };

  it('adds a draft rule for the country picked, for operators only', async () => {
    stats();
    const update = vi.spyOn(apiClient, 'updatePolicy').mockResolvedValue({ ...policy, version: 4 });
    const { unmount } = render(
      <StaticAuthProvider roles={['viewer']}>
        <MapPage route={{ page: 'map', query: { country: 'VN' } }} />
      </StaticAuthProvider>,
    );
    await screen.findByTestId('map-filters');
    await waitFor(() => expect(apiClient.listPolicies).toHaveBeenCalled());
    expect(screen.queryByTestId('map-geo-action')).not.toBeInTheDocument();
    unmount();

    render(
      <StaticAuthProvider roles={['operator']}>
        <MapPage route={{ page: 'map', query: { country: 'VN' } }} />
      </StaticAuthProvider>,
    );
    fireEvent.click(await screen.findByTestId('map-geo-action'));
    fireEvent.click(screen.getByTestId('map-geo-create'));
    await waitFor(() =>
      expect(update).toHaveBeenCalledWith('resource-api', { mode: 'MODE_ENFORCE', geo_rules: [{ countries: ['VN'], action: 'ACTION_BLOCK' }] }, 'e7'),
    );
    expect(await screen.findByTestId('map-geo-result')).toHaveTextContent('Draft version 4 of example-api');
  });

  it('logs an ASN, says when the rule exists, and reports a conflict', async () => {
    stats();
    const update = vi.spyOn(apiClient, 'updatePolicy').mockRejectedValueOnce(new ApiError('conflict', 409));
    render(
      <StaticAuthProvider roles={['operator']}>
        <MapPage route={{ page: 'map', query: { asn: '7552' } }} />
      </StaticAuthProvider>,
    );
    fireEvent.click(await screen.findByTestId('map-geo-action'));
    expect(screen.getByTestId('map-geo-form')).toHaveTextContent('AS7552');
    fireEvent.change(screen.getByTestId('map-geo-mode'), { target: { value: 'ACTION_LOG' } });
    fireEvent.click(screen.getByTestId('map-geo-create'));
    await waitFor(() => expect(update).toHaveBeenCalledWith('resource-api', { mode: 'MODE_ENFORCE', geo_rules: [{ asns: [7552], action: 'ACTION_LOG' }] }, 'e7'));
    expect(await screen.findByTestId('map-geo-result')).toHaveTextContent('Someone saved this policy');

    vi.spyOn(apiClient, 'listPolicies').mockResolvedValue([{ ...policy, spec: { mode: 'MODE_ENFORCE', geo_rules: [{ id: 190000, asns: [7552], action: 'ACTION_LOG' }] } }]);
    update.mockClear();
    fireEvent.click(screen.getByTestId('map-geo-create'));
    await waitFor(() => expect(screen.getByTestId('map-geo-result')).toHaveTextContent('already has a rule'));
    expect(update).not.toHaveBeenCalled();
  });
});
