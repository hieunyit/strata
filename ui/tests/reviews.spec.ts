import { test, expect } from '@playwright/test';
import { signedIn } from './session';

// W13-F-01: the review queue shows a submitted version with its replay and
// its diff; an approver approves it once the replay is done.

const policy = {
  id: 'example-api', name: 'example-api', version: 3, approved_version: 2, deployed_version: 2, etag: 'etag-3',
  spec: { mode: 'MODE_ENFORCE', oversize: 'OVERSIZE_BLOCK' }, created_by: 'lab-operator', update_time: '2026-10-16T08:00:00Z',
};
const submitted = {
  policy_id: 'example-api', version: 3, state: 'SUBMITTED', spec: policy.spec,
  created_by: 'lab-operator', submitted_by: 'lab-operator', create_time: '2026-10-16T07:50:00Z', submit_time: '2026-10-16T08:00:00Z',
};
const versions = [
  submitted,
  { policy_id: 'example-api', version: 2, spec: { mode: 'MODE_SHADOW', oversize: 'OVERSIZE_BLOCK' }, state: 'DEPLOYED', create_time: '2026-10-13T10:00:00Z', created_by: 'lab-operator' },
];
const replay = {
  id: 'op-0123456789abcdef01234567', kind: 'REPLAY', state: 'DONE', done: true, policy_id: 'example-api', version: 3,
  replay: {
    samples: '5481', elapsed_ms: '812', baseline_bundle: '41', sample_files: 3, sample_bytes: '1048576',
    traffic: {
      samples: '1200', newly_blocked: '2', newly_allowed: '0',
      draft_actions: { allow: '1198', block: '2' }, baseline_actions: { allow: '1200' },
      newly_blocked_rules: { '942100': '2' }, newly_blocked_paths: { '/v1/login': '2' }, newly_blocked_sampled: { allow: '2' },
      examples_blocked: [{ ts_ms: '1792140000000', node_id: 'node-1', method: 'POST', raw_uri: '/v1/login?user=hmac:5f2b9c', draft: 'block', baseline: 'log', draft_rules: [942100], baseline_rules: [] }],
    },
    corpus: {
      samples: '4281', newly_blocked: '1700', newly_allowed: '0',
      newly_blocked_rules: { '942100': '640', '941100': '410', '930100': '220' }, newly_blocked_paths: { '/': '1700' },
    },
  },
};

test('approve a submitted version after its replay', async ({ page }) => {
  await signedIn(page, ['approver'], 'lab-approver');
  await page.route('**/v1/policies', (r) => r.fulfill({ json: { policies: [policy] } }));
  await page.route('**/v1/policies/-/versions?state=SUBMITTED', (r) => r.fulfill({ json: { versions: [submitted] } }));
  await page.route('**/v1/policies/example-api/versions', (r) => r.fulfill({ json: { versions } }));
  await page.route('**/v1/policies/example-api/versions/3/replay', (r) => r.fulfill({ json: { operation: replay } }));
  let body: unknown;
  await page.route('**/v1/policies/example-api:approve', async (r) => {
    body = r.request().postDataJSON();
    await r.fulfill({ json: { version: { ...submitted, state: 'APPROVED', decided_by: 'lab-approver' } } });
  });
  await page.goto('/#/reviews');

  await expect(page.getByTestId('nav-reviews')).toBeVisible();
  await expect(page.getByTestId('review-row').getByTestId('replay-state')).toHaveText('done');
  await page.getByTestId('review-row').click();
  await expect(page.getByTestId('replay-traffic-blocked')).toHaveText('2');
  await expect(page.getByTestId('replay-corpus-blocked')).toHaveText('1,700');
  await expect(page.getByTestId('replay-traffic-examples')).toContainText('/v1/login?user=hmac:5f2b9c');
  await expect(page.getByTestId('diff-from')).toHaveValue('2');
  await expect(page.getByTestId('diff-to')).toHaveValue('3');
  await page.getByTestId('review-comment').fill('2 new blocks on /v1/login are attacks');
  await page.screenshot({ path: '../docs/reports/w13/f01-review-queue.png', fullPage: true });

  await page.getByTestId('review-approve').click();
  await expect(page.getByTestId('review-done')).toContainText('example-api v3 approved');
  expect(body).toEqual({ version: 3, comment: '2 new blocks on /v1/login are attacks' });
});

test('an operator submits the newest draft', async ({ page }) => {
  await signedIn(page, ['operator'], 'lab-operator');
  let state = 'DRAFT';
  await page.route('**/v1/policies', (r) => r.fulfill({ json: { policies: [policy] } }));
  await page.route('**/v1/policies/example-api/versions', (r) => r.fulfill({ json: { versions: [{ ...submitted, state }, versions[1]] } }));
  await page.route('**/v1/policies/example-api:submit', async (r) => {
    state = 'SUBMITTED';
    await r.fulfill({ json: { version: submitted } });
  });
  await page.goto('/#/policies');
  await page.getByTestId('policy-row').click();
  await page.getByTestId('policy-submit').click();
  await expect(page.getByTestId('policy-submitted')).toContainText('Version 3 submitted for review');
  await expect(page.getByTestId('policy-version-state').first()).toHaveText('submitted');
  await expect(page.getByTestId('policy-submit')).toHaveCount(0);
});
