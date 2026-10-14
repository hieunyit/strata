import { test, expect } from '@playwright/test';
import { signedIn } from './session';

// W11-F-01: an operator edits a policy in the form and in YAML, the two
// stay in sync, and the save is a PATCH with the etag (a new draft version).

const policy = {
  id: 'example-api', name: 'example-api', version: 3, etag: 'etag-3',
  spec: { mode: 'MODE_SHADOW', oversize: 'OVERSIZE_PASS' }, created_by: 'lab-operator',
  update_time: '2026-10-13T10:00:00Z',
};

test('form and YAML stay in sync; save makes a draft version', async ({ page }) => {
  await signedIn(page, ['operator'], 'lab-operator');
  let patched: unknown;
  const versions = [{ policy_id: 'example-api', version: 3, spec: policy.spec, state: 'DEPLOYED', create_time: '2026-10-13T10:00:00Z', created_by: 'lab-operator' }];
  await page.route('**/v1/policies', (r) => r.fulfill({ json: { policies: [policy] } }));
  await page.route('**/v1/policies/example-api/versions', (r) => r.fulfill({ json: { versions } }));
  await page.route('**/v1/policies/example-api', async (r) => {
    if (r.request().method() !== 'PATCH') return r.fallback();
    patched = r.request().postDataJSON();
    versions.unshift({ policy_id: 'example-api', version: 4, spec: { mode: 'MODE_ENFORCE', oversize: 'OVERSIZE_BLOCK' }, state: 'DRAFT', create_time: '2026-10-14T01:00:00Z', created_by: 'lab-operator' });
    await r.fulfill({ json: { policy: { ...policy, version: 4, etag: 'etag-4', spec: versions[0].spec } } });
  });
  await page.goto('/#/policies');

  await page.getByTestId('policy-row').click();
  await page.getByTestId('policy-edit').click();
  const yaml = page.getByTestId('editor-yaml');
  await expect(yaml).toHaveValue('mode: shadow\noversize: pass\n');

  // form -> YAML
  await page.getByTestId('editor-mode-MODE_ENFORCE').check();
  await page.getByTestId('editor-guard-cccd').check();
  await expect(yaml).toHaveValue('mode: enforce\noversize: pass\nresponse:\n  data_guard: [cccd]\n');

  // YAML -> form, with an error on the way
  await yaml.fill('mode: enforce\noversize: drop\n');
  await expect(page.getByTestId('editor-yaml-error')).toHaveText('Line 2: oversize is pass or block');
  await expect(page.getByTestId('editor-save')).toBeDisabled();
  await yaml.fill('mode: enforce\noversize: block\n');
  await expect(page.getByTestId('editor-oversize')).toHaveValue('OVERSIZE_BLOCK');
  await expect(page.getByTestId('editor-guard-cccd')).not.toBeChecked();
  await page.screenshot({ path: '../docs/reports/w11/f01-policy-editor.png', fullPage: true });

  await page.getByTestId('editor-save').click();
  await expect(page.getByTestId('editor-saved')).toHaveText('Saved as draft version 4.');
  expect(patched).toEqual({ etag: 'etag-3', spec: { mode: 'MODE_ENFORCE', oversize: 'OVERSIZE_BLOCK' } });
  await expect(page.getByTestId('policy-version-state')).toHaveText(['draft', 'deployed']);
});
