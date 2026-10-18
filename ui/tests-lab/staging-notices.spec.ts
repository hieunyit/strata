import { test, expect } from '@playwright/test';
import path from 'path';

// Own local-auth/API/PostgreSQL fixture, launched by the Go browser test.
// No requests are mocked and no existing lab's credentials/ports are used.
test('reviewer sees durable history in English/Vietnamese and on mobile; viewer cannot read it', async ({ page, baseURL }) => {
  const password = process.env.STRATA_NOTICE_LAB_PASSWORD;
  const output = process.env.STRATA_NOTICE_EVIDENCE_DIR;
  if (!password || !output || !baseURL) throw new Error('Isolated notice fixture is required');
  const external: string[] = [];
  await page.route('**/*', async (route) => {
    const url = new URL(route.request().url());
    if (url.origin !== new URL(baseURL).origin) { external.push(url.origin + url.pathname); await route.abort(); return; }
    await route.continue();
  });
  const errors: string[] = [];
  page.on('pageerror', (error) => errors.push(error.message));
  await page.goto('/');
  await page.getByTestId('login-username').fill('example-reviewer');
  await page.getByTestId('login-password').fill(password);
  await page.getByTestId('password-login-btn').click();
  await expect(page.getByTestId('staging-unread')).toBeVisible();
  await page.getByTestId('staging-notices-toggle').click();
  await expect(page.getByText('Rollout: Waiting to start')).toBeVisible();
  await expect(page.getByText(/5 reported FP \/ 18446744073709551615/)).toBeVisible();
  await page.screenshot({ path: path.join(output, 'reviewer-en.png'), fullPage: true });
  await page.getByTestId('language-toggle-btn').click();
  await page.getByTestId('staging-notices-toggle').click();
  await expect(page.getByText('Rollout: Chờ bắt đầu')).toBeVisible();
  await page.screenshot({ path: path.join(output, 'reviewer-vi.png'), fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  const panel = page.locator('#staging-notice-panel');
  const box = await panel.boundingBox();
  expect(box).not.toBeNull();
  expect(box!.x).toBeGreaterThanOrEqual(0);
  expect(box!.x + box!.width).toBeLessThanOrEqual(390);
  await page.screenshot({ path: path.join(output, 'reviewer-mobile.png'), fullPage: true });
  await page.keyboard.press('Escape');
  await page.getByTestId('logout-btn').click();
  await page.getByTestId('login-username').fill('example-viewer');
  await page.getByTestId('login-password').fill(password);
  await page.getByTestId('password-login-btn').click();
  await expect(page.getByTestId('current-role')).toHaveText('Viewer');
  await expect(page.getByTestId('staging-notices-toggle')).toHaveCount(0);
  const status = await page.evaluate(async () => {
    const session = JSON.parse(sessionStorage.getItem('strata.localSession') ?? '{}') as { token: string };
    const response = await fetch('/v1/rules/staging-actions', { headers: { Authorization: `Bearer ${session.token}` } });
    return response.status;
  });
  expect(status).toBe(403);
  expect(errors).toEqual([]);
  expect(external).toEqual([]);
});
