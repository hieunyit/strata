import { test, expect } from '@playwright/test';
import fs from 'fs';
import path from 'path';

test('exact-version replay, four eyes, rejection and approval pin through real API', async ({ page, baseURL }) => {
  const password = process.env.STRATA_REVIEW_LAB_PASSWORD, output = process.env.STRATA_REVIEW_EVIDENCE_DIR;
  if (!password || !output || !baseURL) throw new Error('Private review fixture required');
  const errors: string[] = [], external: string[] = [];
  const writes: { path: string; status: number; version?: number; expected_replay_id?: string }[] = [];
  page.on('pageerror', e => errors.push(e.message));
  page.on('response', response => {
    const req = response.request(), url = new URL(req.url());
    if (req.method() === 'POST' && url.pathname.startsWith('/v1/policies/')) {
      const body = req.postDataJSON(); writes.push({ path: url.pathname, status: response.status(), version: body.version, expected_replay_id: body.expected_replay_id });
    }
  });
  await page.route('**/*', async route => {
    const url = new URL(route.request().url());
    if (url.origin !== new URL(baseURL).origin) { external.push(url.origin); await route.abort(); return; }
    await route.continue();
  });
  const login = async (name: string, route: 'policies' | 'reviews') => {
    if (await page.getByTestId('logout-btn').count()) await page.getByTestId('logout-btn').click();
    await page.goto(`/#/${route}`);
    await page.getByTestId('login-username').fill(`example-${name}`);
    await page.getByTestId('login-password').fill(password);
    await page.getByTestId('password-login-btn').click();
    await expect(page.getByTestId(route === 'policies' ? 'policies-table' : 'reviews-table')).toBeVisible();
  };
  const inspect = async (where: 'policies' | 'reviews') => {
    if (where === 'policies') {
      await page.getByTestId('policy-row').click();
      await page.getByTestId('policy-version-row').filter({ hasText: /^v2/ }).getByRole('button', { name: 'Inspect version' }).click();
    } else await page.getByTestId('review-row').getByRole('button', { name: 'Inspect version' }).click();
    await expect(page.getByTestId('version-review')).toContainText('resource-api · v2');
  };
  const inspector = page.getByTestId('version-review');
  const write = async (verb: string, button: string, status: number) => {
    const response = page.waitForResponse(r => r.request().method() === 'POST' && r.url().endsWith(`/v1/policies/resource-api:${verb}`));
    await inspector.getByRole('button', { name: button, exact: true }).click();
    const result = await response; expect(result.status()).toBe(status); return result;
  };
  await login('writer', 'policies'); await inspect('policies');
  await write('replay', 'Run replay', 200);
  await expect.poll(async () => {
    await inspector.getByRole('button', { name: 'Reload review' }).click();
    await expect(inspector.getByTestId('replay-summary')).toBeVisible();
    return await inspector.getByTestId('replay-summary').textContent();
  }).toContain('Done');
  await write('submit', 'Submit for review', 200);
  await expect(inspector.getByRole('checkbox')).toBeVisible();
  const firstId = (await inspector.getByRole('checkbox').getAttribute('aria-label')) ?? (await inspector.getByRole('checkbox').locator('..').textContent())!;
  await inspector.getByRole('checkbox').check(); await write('approve', 'Approve version', 403);
  await expect(inspector.getByRole('alert')).toContainText('Reload review');
  await login('reviewer', 'reviews'); await inspect('reviews');
  await expect(inspector.getByTestId('diff-from')).toHaveValue('1'); await expect(inspector.getByTestId('diff-to')).toHaveValue('2');
  await expect(inspector.getByRole('button', { name: 'Run replay' })).toHaveCount(0);
  await inspector.getByRole('textbox').fill('needs a second look'); await write('reject', 'Reject version', 200);
  await expect(inspector).toContainText('Version rejected with the recorded reason.');
  await expect(inspector.getByTestId('decision-reason')).toHaveText('needs a second look');
  await login('writer', 'policies'); await inspect('policies');
  await expect(inspector.getByTestId('decision-reason')).toHaveText('needs a second look');
  await write('submit', 'Submit for review', 200);
  await login('reviewer', 'reviews'); await inspect('reviews');
  await expect(inspector.getByRole('checkbox')).toBeVisible();
  await page.screenshot({ path: path.join(output, 'review-en.png'), fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 }); await page.getByTestId('language-toggle-btn').click();
  await expect(inspector).toContainText('Tôi đã xem report replay');
  const box = await inspector.boundingBox(); expect(box).not.toBeNull(); expect(box!.x).toBeGreaterThanOrEqual(0); expect(box!.x + box!.width).toBeLessThanOrEqual(390);
  await page.screenshot({ path: path.join(output, 'review-mobile-vi.png'), fullPage: true });
  await page.getByTestId('language-toggle-btn').click();
  await inspector.getByRole('checkbox').check(); const stale = await write('approve', 'Approve version', 400);
  const oldPin = stale.request().postDataJSON().expected_replay_id;
  expect(firstId).toContain(oldPin);
  await expect(inspector.getByRole('alert')).toContainText('Reload review'); await expect(inspector.getByRole('button', { name: 'Approve version' })).toBeDisabled();
  await inspector.getByRole('button', { name: 'Reload review' }).click();
  await expect(inspector.getByRole('checkbox')).toBeVisible(); await expect(inspector.getByRole('checkbox')).not.toBeChecked();
  await expect(inspector.getByRole('checkbox').locator('..')).not.toContainText(oldPin);
  await inspector.getByRole('checkbox').check(); const approved = await write('approve', 'Approve version', 200);
  const pin = approved.request().postDataJSON().expected_replay_id; expect(pin).not.toBe(oldPin);
  await expect(inspector).toContainText('Version approved. Deployment is a separate action.');
  await expect(inspector.getByTestId('approved-replay-id')).toHaveText(pin);
  // A later real replay compares enforce with the now-approved enforce
  // baseline. It must not replace the approved shadow->enforce report.
  await login('writer', 'policies'); await inspect('policies');
  await write('replay', 'Run replay', 200);
  await expect.poll(async () => {
    await inspector.getByRole('button', { name: 'Reload review' }).click();
    await expect(inspector.getByTestId('replay-summary')).toBeVisible();
    return await inspector.getByTestId('replay-summary').textContent();
  }).toContain('Done');
  await expect(inspector.getByTestId('approved-replay-id')).toHaveText(pin);
  await expect(inspector.getByRole('note')).toContainText('does not replace the report used for approval');
  await page.screenshot({ path: path.join(output, 'approved-with-later-replay-en.png'), fullPage: true });

  await page.setViewportSize({ width: 1280, height: 900 }); await login('viewer', 'policies'); await inspect('policies');
  await expect(inspector.getByTestId('replay-summary')).toBeVisible(); await expect(inspector.getByTestId('review-actions')).toHaveCount(0);
  const denied = await page.evaluate(async expected_replay_id => {
    const session = JSON.parse(sessionStorage.getItem('strata.localSession') ?? '{}');
    return (await fetch('/v1/policies/resource-api:approve', { method: 'POST', headers: { Authorization: `Bearer ${session.token}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ version: 2, expected_replay_id }) })).status;
  }, pin);
  expect(denied).toBe(403); expect(errors).toEqual([]); expect(external).toEqual([]);
  expect(writes.map(w => [w.path.split(':').at(-1), w.status])).toEqual([['replay',200],['submit',200],['approve',403],['reject',200],['submit',200],['approve',400],['approve',200],['replay',200],['approve',403]]);
  fs.writeFileSync(path.join(output, 'browser-result.json'), JSON.stringify({ writes, old_pin: oldPin, approved_pin: pin, viewer_denied: denied, errors, external, mobile_bounds: box, scope: 'real local auth/API/PostgreSQL and Rust replay worker; deliberate newer replay before approval handler; no deployment/NGINX/ClickHouse' }, null, 2) + '\n');
});
