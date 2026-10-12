import { test, expect, type Page } from '@playwright/test';
import { signedIn } from './session';

// W07-F-01: nodes by group with versions and bundle state, and the rollout
// in progress; the page follows state changes as the API reports them.

const groups = { groups: [{ id: 'lab', name: 'Lab' }, { id: 'edge', name: 'Edge' }] };

const node = (id: string, host: string, group: string, version: string, state: string) => ({
  id, hostname: host, group_id: group, online: true, proxy_version: '1.30.5', module_version: '0.1.0',
  bundle_version: version, bundle_state: state, last_seen_time: new Date().toISOString(),
});

// a scripted API: the page polls every 3 s; poll k (at about 3k s after
// the first request) gets step k, the same for all its calls
async function scripted(page: Page, steps: { nodes: object[]; rollout: object }[]) {
  let start = 0;
  const step = () => {
    start ||= Date.now();
    return steps[Math.min(Math.floor((Date.now() - start + 1500) / 3000), steps.length - 1)];
  };
  await page.route('**/v1/groups', (r) => r.fulfill({ json: groups }));
  await page.route('**/v1/nodes', (r) => r.fulfill({ json: { nodes: step().nodes } }));
  await page.route('**/v1/rollouts', (r) => r.fulfill({ json: { rollouts: [step().rollout] } }));
  await page.route('**/v1/rollouts/*', (r) => r.fulfill({ json: { rollout: step().rollout } }));
}

const rollout = (state: string, wave: number, nodes: [string, number, string, string?][], reason = '') => ({
  id: '12', bundle_version: '12', state, waves: [1, 2], current_wave: wave, reason,
  nodes: nodes.map(([node_id, w, s, error]) => ({ node_id, wave: w, state: s, error: error ?? '' })),
});

test('a node goes VERIFIED then ACTIVE, the next wave starts', async ({ page }) => {
  await signedIn(page, ['viewer'], 'lab-viewer');
  await scripted(page, [
    {
      nodes: [node('node-a', 'edge-01', 'lab', '12', 'VERIFIED'), node('node-b', 'edge-02', 'edge', '11', 'ACTIVE')],
      rollout: rollout('RUNNING', 0, [['node-a', 0, 'VERIFIED'], ['node-b', 1, 'PENDING']]),
    },
    {
      nodes: [node('node-a', 'edge-01', 'lab', '12', 'ACTIVE'), node('node-b', 'edge-02', 'edge', '12', 'DOWNLOADING')],
      rollout: rollout('RUNNING', 1, [['node-a', 0, 'ACTIVE'], ['node-b', 1, 'DOWNLOADING']]),
    },
    {
      nodes: [node('node-a', 'edge-01', 'lab', '12', 'ACTIVE'), node('node-b', 'edge-02', 'edge', '12', 'ACTIVE')],
      rollout: rollout('RUNNING', 1, [['node-a', 0, 'ACTIVE'], ['node-b', 1, 'ACTIVE']]),
    },
  ]);
  await page.goto('/#/fleet');

  // grouped by connector group, with the versions
  await expect(page.getByTestId('group')).toHaveCount(2);
  const a = page.locator('[data-testid="node-row"][data-node="node-a"]');
  await expect(a.getByTestId('node-nginx')).toHaveText('1.30.5');
  await expect(a.getByTestId('node-module')).toHaveText('0.1.0');
  await expect(page.locator('[data-group="lab"]')).toContainText('edge-01');
  await expect(page.locator('[data-group="edge"]')).toContainText('edge-02');

  // VERIFIED, then ACTIVE as the polls go
  await expect(a.getByTestId('node-bundle-state')).toHaveAttribute('data-state', 'VERIFIED');
  await expect(page.getByTestId('rollout-wave')).toHaveText('đợt 1/2');
  await expect(a.getByTestId('node-bundle-state')).toHaveAttribute('data-state', 'ACTIVE', { timeout: 10_000 });
  await expect(page.getByTestId('rollout-wave')).toHaveText('đợt 2/2');
  const b = page.locator('[data-testid="rollout-node"][data-node="node-b"]');
  await expect(b).toHaveAttribute('data-state', 'ACTIVE', { timeout: 10_000 });
  // read-only: no action besides exporting what is shown
  await expect(page.locator('main button:not([data-testid="export-csv-btn"])')).toHaveCount(0);
});

test('a FAILED node stops the rollout and shows why', async ({ page }) => {
  await signedIn(page, ['operator']);
  await scripted(page, [
    {
      nodes: [node('node-a', 'edge-01', 'lab', '11', 'DOWNLOADING')],
      rollout: rollout('RUNNING', 0, [['node-a', 0, 'DOWNLOADING']]),
    },
    {
      nodes: [node('node-a', 'edge-01', 'lab', '12', 'FAILED')],
      rollout: rollout('FAILED', 0, [['node-a', 0, 'FAILED', 'signature does not verify']],
        'node node-a failed bundle 12: signature does not verify'),
    },
  ]);
  await page.goto('/#/fleet');
  const a = page.locator('[data-testid="node-row"][data-node="node-a"]');
  await expect(a.getByTestId('node-bundle-state')).toHaveAttribute('data-state', 'DOWNLOADING');
  await expect(page.getByTestId('rollout-state')).toHaveAttribute('data-state', 'FAILED', { timeout: 10_000 });
  await expect(a.getByTestId('node-bundle-state')).toHaveAttribute('data-state', 'FAILED');
  await expect(page.getByTestId('rollout-reason')).toContainText('signature does not verify');
  await expect(page.locator('[data-testid="rollout-node"][data-node="node-a"]')).toHaveAttribute('title', 'signature does not verify');
});

test('Vietnamese by default, English on switch', async ({ page }) => {
  await signedIn(page, ['viewer']);
  await scripted(page, [{ nodes: [node('node-a', 'edge-01', 'lab', '12', 'ACTIVE')], rollout: { id: '9', state: 'DONE' } }]);
  await page.goto('/#/fleet');
  await expect(page.getByTestId('rollout-none')).toHaveText('Không có rollout đang chạy.');
  await expect(page.getByTestId('node-bundle-state')).toHaveText('đang dùng');
  await page.getByTestId('language-toggle-btn').click();
  await expect(page.getByTestId('rollout-none')).toHaveText('No rollout in progress.');
  await expect(page.getByTestId('node-bundle-state')).toHaveText('active');
});
