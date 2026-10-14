import { test, expect } from '@playwright/test';
import { signedIn } from './session';

// W12-F-01: pick two versions of a policy and see the diff block by block.

const policy = {
  id: 'example-api', name: 'example-api', version: 3, etag: 'etag-3',
  spec: { mode: 'MODE_ENFORCE', oversize: 'OVERSIZE_BLOCK' }, created_by: 'lab-operator',
  update_time: '2026-10-14T10:00:00Z',
};
const versions = [
  { policy_id: 'example-api', version: 3, spec: policy.spec, state: 'DRAFT', create_time: '2026-10-14T10:00:00Z', created_by: 'lab-operator' },
  { policy_id: 'example-api', version: 2, spec: { mode: 'MODE_SHADOW', response: { db_errors: true, data_guard: ['cccd'] } }, state: 'DEPLOYED', create_time: '2026-10-13T10:00:00Z', created_by: 'lab-operator' },
  { policy_id: 'example-api', version: 1, spec: { mode: 'MODE_SHADOW' }, state: 'DEPLOYED', create_time: '2026-10-12T10:00:00Z', created_by: 'lab-admin' },
];

test('compare two versions block by block', async ({ page }) => {
  await signedIn(page, ['viewer'], 'lab-viewer');
  await page.route('**/v1/policies', (r) => r.fulfill({ json: { policies: [policy] } }));
  await page.route('**/v1/policies/example-api/versions', (r) => r.fulfill({ json: { versions } }));
  await page.goto('/#/policies');

  await page.getByTestId('policy-row').click();
  await page.getByTestId('policy-compare').click();
  await expect(page.getByTestId('diff-from')).toHaveValue('2');
  await expect(page.getByTestId('diff-to')).toHaveValue('3');
  await expect(page.getByTestId('diff-summary')).toHaveText('4 fields changed');
  const general = page.getByTestId('diff-block-general');
  await expect(general.locator('[data-changed="true"] code')).toHaveText(['mode', 'oversize']);
  const response = page.getByTestId('diff-block-response');
  await expect(response.locator('[data-changed="true"] code')).toHaveText(['db_errors', 'data_guard']);
  await expect(response.getByTestId('diff-removed')).toHaveText('−cccd');
  await page.screenshot({ path: '../docs/reports/w12/f01-policy-diff.png', fullPage: true });

  await page.getByTestId('diff-from').selectOption('1');
  await expect(page.getByTestId('diff-summary')).toHaveText('2 fields changed');
  await expect(page.getByTestId('diff-block-response').getByTestId('diff-block-count')).toHaveText('unchanged');
});
