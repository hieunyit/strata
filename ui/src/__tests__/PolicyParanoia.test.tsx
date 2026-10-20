import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { PolicyEditor } from '../components/policy/PolicyEditor';
import { apiClient } from '../api/client';
import { mergeYamlSpec, normalizeSpec, specToYaml, yamlToSpec } from '../lib/policyYaml';
import { diffSpecs } from '../lib/policyDiff';
import i18n from '../i18n';

beforeEach(() => { vi.restoreAllMocks(); void i18n.changeLanguage('en'); });

// W17-S-01: CRS paranoia levels, enforced and in shadow.
describe('CRS paranoia levels', () => {
  it('are stored as the API stores them', () => {
    expect(normalizeSpec({ mode: 'MODE_SHADOW', crs_paranoia: 1, crs_paranoia_shadow: 1 })).toEqual({ mode: 'MODE_SHADOW' });
    expect(normalizeSpec({ mode: 'MODE_SHADOW', crs_paranoia: 0, crs_paranoia_shadow: 0 })).toEqual({ mode: 'MODE_SHADOW' });
    expect(normalizeSpec({ mode: 'MODE_SHADOW', crs_paranoia_shadow: 2 })).toEqual({ mode: 'MODE_SHADOW', crs_paranoia_shadow: 2 });
    expect(normalizeSpec({ mode: 'MODE_SHADOW', crs_paranoia: 2, crs_paranoia_shadow: 2 })).toEqual({ mode: 'MODE_SHADOW', crs_paranoia: 2 });
    // a shadow level below the enforced one means none
    expect(normalizeSpec({ mode: 'MODE_SHADOW', crs_paranoia: 3, crs_paranoia_shadow: 2 })).toEqual({ mode: 'MODE_SHADOW', crs_paranoia: 3 });
  });

  it('read and write YAML', () => {
    const spec = { mode: 'MODE_ENFORCE' as const, crs_paranoia: 2, crs_paranoia_shadow: 3 };
    const text = specToYaml(spec);
    expect(text).toBe('mode: enforce\ncrs_paranoia: 2\ncrs_paranoia_shadow: 3\n');
    expect(yamlToSpec(text).spec).toEqual(spec);
    expect(specToYaml({ mode: 'MODE_SHADOW', crs_paranoia_shadow: 2 })).toBe('mode: shadow\ncrs_paranoia_shadow: 2\n');
    expect(yamlToSpec('mode: shadow\ncrs_paranoia: 5\n').error).toMatchObject({ line: 2, code: 'paranoia' });
    expect(yamlToSpec('mode: shadow\ncrs_paranoia: two\n').error).toMatchObject({ line: 2, code: 'paranoia' });
    expect(yamlToSpec('mode: shadow\ncrs_paranoia: 3\ncrs_paranoia_shadow: 2\n').error).toMatchObject({ line: 3, code: 'paranoiaShadow' });
    // removing the keys from the YAML resets the levels, other settings kept
    expect(mergeYamlSpec({ mode: 'MODE_SHADOW', crs_paranoia_shadow: 2, max_args: 200 }, { mode: 'MODE_SHADOW' }))
      .toEqual({ mode: 'MODE_SHADOW', max_args: 200 });
  });

  it('show in the general block of the diff, with defaults', () => {
    const general = diffSpecs({ mode: 'MODE_SHADOW' }, { mode: 'MODE_SHADOW', crs_paranoia_shadow: 2 })
      .find((b) => b.block === 'general')!;
    expect(general.changed).toBe(1);
    expect(general.fields.find((f) => f.key === 'crs_paranoia')).toMatchObject({ from: '1', to: '1', changed: false });
    expect(general.fields.find((f) => f.key === 'crs_paranoia_shadow')).toMatchObject({ from: '1', to: '2', changed: true });
    expect(diffSpecs({ mode: 'MODE_SHADOW', crs_paranoia_shadow: 2 }, { mode: 'MODE_SHADOW' }).find((b) => b.block === 'advanced')).toBeUndefined();
  });

  it('are set in the form, the shadow level never below the enforced one', async () => {
    const update = vi.spyOn(apiClient, 'updatePolicy').mockResolvedValue({ id: 'resource-api', version: 2 });
    render(<PolicyEditor policy={{ id: 'resource-api', name: 'example-api', etag: 'e1', spec: { mode: 'MODE_SHADOW' } }} onSaved={vi.fn()} onCancel={vi.fn()} />);
    fireEvent.change(screen.getByTestId('editor-paranoia-shadow'), { target: { value: '2' } });
    expect(screen.getByTestId('editor-yaml')).toHaveValue('mode: shadow\ncrs_paranoia_shadow: 2\n');
    fireEvent.change(screen.getByTestId('editor-paranoia'), { target: { value: '3' } });
    expect(screen.getByTestId('editor-paranoia-shadow')).toHaveValue('3');
    expect(screen.getByTestId('editor-yaml')).toHaveValue('mode: shadow\ncrs_paranoia: 3\n');
    fireEvent.change(screen.getByTestId('editor-paranoia'), { target: { value: '2' } });
    fireEvent.change(screen.getByTestId('editor-paranoia-shadow'), { target: { value: '4' } });
    fireEvent.click(screen.getByTestId('editor-save'));
    await waitFor(() => expect(update).toHaveBeenCalledWith('resource-api', { mode: 'MODE_SHADOW', crs_paranoia: 2, crs_paranoia_shadow: 4 }, 'e1'));
    expect(screen.queryByTestId('editor-advanced')).not.toBeInTheDocument();
  });
});

// W17-S-01: CRS plugins.
describe('CRS plugins', () => {
  it('are stored sorted, none is absent, YAML both ways', () => {
    expect(normalizeSpec({ mode: 'MODE_SHADOW', crs_plugins: ['wordpress', 'drupal'] })).toEqual({ mode: 'MODE_SHADOW', crs_plugins: ['drupal', 'wordpress'] });
    expect(normalizeSpec({ mode: 'MODE_SHADOW', crs_plugins: [] })).toEqual({ mode: 'MODE_SHADOW' });
    expect(specToYaml({ mode: 'MODE_SHADOW', crs_plugins: ['wordpress', 'drupal'] })).toBe('mode: shadow\ncrs_plugins: [drupal, wordpress]\n');
    expect(yamlToSpec('mode: shadow\ncrs_plugins: [wordpress]\n').spec).toEqual({ mode: 'MODE_SHADOW', crs_plugins: ['wordpress'] });
    expect(yamlToSpec('mode: shadow\ncrs_plugins:\n  - nextcloud\n  - drupal\n').spec).toEqual({ mode: 'MODE_SHADOW', crs_plugins: ['nextcloud', 'drupal'] });
    expect(yamlToSpec('mode: shadow\ncrs_plugins: [WordPress]\n').error).toMatchObject({ line: 2, code: 'plugin' });
    expect(yamlToSpec('mode: shadow\ncrs_plugins: [drupal, drupal]\n').error).toMatchObject({ line: 2, code: 'pluginTwice' });
    const general = diffSpecs({ mode: 'MODE_SHADOW' }, { mode: 'MODE_SHADOW', crs_plugins: ['wordpress'] }).find((b) => b.block === 'general')!;
    expect(general.fields.find((f) => f.key === 'crs_plugins')).toMatchObject({ from: '[]', to: '[wordpress]', changed: true });
  });

  it('are picked in the form and saved', async () => {
    const update = vi.spyOn(apiClient, 'updatePolicy').mockResolvedValue({ id: 'resource-api', version: 2 });
    render(<PolicyEditor policy={{ id: 'resource-api', name: 'example-api', etag: 'e1', spec: { mode: 'MODE_SHADOW' } }} onSaved={vi.fn()} onCancel={vi.fn()} />);
    fireEvent.click(screen.getByTestId('editor-plugin-wordpress'));
    fireEvent.click(screen.getByTestId('editor-plugin-drupal'));
    expect(screen.getByTestId('editor-yaml')).toHaveValue('mode: shadow\ncrs_plugins: [drupal, wordpress]\n');
    fireEvent.click(screen.getByTestId('editor-plugin-drupal'));
    fireEvent.click(screen.getByTestId('editor-save'));
    await waitFor(() => expect(update).toHaveBeenCalledWith('resource-api', { mode: 'MODE_SHADOW', crs_plugins: ['wordpress'] }, 'e1'));
  });
});
