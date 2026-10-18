import { test, expect } from '@playwright/test';
import fs from 'fs';
import path from 'path';

test('operator creates scoped draft through real API; viewer and approver cannot write', async ({ page, baseURL }) => {
  const password = process.env.STRATA_EXCEPTION_LAB_PASSWORD, output = process.env.STRATA_EXCEPTION_EVIDENCE_DIR;
  if (!password || !output || !baseURL) throw new Error('Isolated exception fixture required');
  const external: string[] = [], errors: string[] = [], writes: string[] = [];
  page.on('request', (request) => { const p = new URL(request.url()).pathname; if (request.method() === 'POST' && p !== '/v1/auth/login') writes.push(p); });
  page.on('pageerror', (error) => errors.push(error.message));
  await page.route('**/*', async (route) => {
    const url = new URL(route.request().url());
    if (url.origin !== new URL(baseURL).origin) { external.push(url.origin); await route.abort(); return; }
    await route.continue();
  });
  const login = async (role: string) => {
    await page.getByTestId('login-username').fill(`example-${role}`);
    await page.getByTestId('login-password').fill(password);
    await page.getByTestId('password-login-btn').click();
    await expect(page.getByTestId('detail-block-id')).toBeVisible();
  };
  await page.goto('/#/events/STR-0000-0000-0000-0001');
  await login('operator');
  await page.getByRole('button', { name: 'Create exception', exact: true }).click();
  await expect(page.getByText('Policy example-api · version 1')).toBeVisible();
  await expect(page.getByTestId('exception-route')).toHaveText('Request routeGET api.example.test/search');
  await expect(page.getByLabel('Rule and field').locator('option')).toHaveCount(2);
  await expect(page.getByLabel('Duration')).toHaveValue('3600');
  await page.screenshot({ path: path.join(output, 'operator-prefill-en.png'), fullPage: true });
  await page.getByLabel('Reason', { exact: true }).fill('example legitimate request');
  const write = page.waitForResponse((response) => response.url().endsWith('/v1/exceptions:fromBlockId') && response.request().method() === 'POST');
  await page.getByRole('button', { name: 'Create draft', exact: true }).click();
  const response = await write;
  expect(response.status()).toBe(200);
  const receipt = await response.json();
  expect(receipt.state).toBe('DRAFT'); expect(receipt.policy_id).toBe('resource-api'); expect(receipt.policy_version).toBe(2);
  await expect(page.getByTestId('exception-created')).toContainText('Draft version 2 created');
  await page.getByTestId('language-toggle-btn').click();
  await expect(page.getByTestId('exception-created')).toContainText('Đã tạo bản nháp phiên bản 2');
  await page.screenshot({ path: path.join(output, 'operator-created-vi.png'), fullPage: true });
  await page.getByRole('button', { name: 'Đóng', exact: true }).click();
  await page.setViewportSize({ width: 390, height: 844 });
  await page.getByRole('button', { name: 'Tạo exception', exact: true }).click();
  await expect(page.getByText('Policy example-api · phiên bản 2')).toBeVisible();
  const form = page.getByTestId('exception-form');
  const box = await form.boundingBox(); expect(box).not.toBeNull();
  expect(box!.x).toBeGreaterThanOrEqual(0); expect(box!.x + box!.width).toBeLessThanOrEqual(390);
  await page.screenshot({ path: path.join(output, 'operator-mobile-vi.png'), fullPage: true });
  await page.keyboard.press('Escape');
  await expect(form).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Tạo exception', exact: true })).toBeFocused();
  const denied: Record<string, number> = {};
  for (const role of ['viewer', 'approver']) {
    await page.getByTestId('logout-btn').click(); await login(role);
    await expect(page.getByRole('button', { name: 'Tạo exception', exact: true })).toHaveCount(0);
    denied[role] = await page.evaluate(async (etag) => {
      const session = JSON.parse(sessionStorage.getItem('strata.localSession') ?? '{}') as { token: string };
      const result = await fetch('/v1/exceptions:fromBlockId', { method: 'POST', headers: { Authorization: `Bearer ${session.token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ block_id: 'STR-0000-0000-0000-0001', rule_id: 700011, field: 'ARGS:Name', reason: 'must be refused', ttl_seconds: 3600, etag, request_id: crypto.randomUUID() }) });
      return result.status;
    }, receipt.etag);
    expect(denied[role]).toBe(403);
  }
  expect(errors).toEqual([]); expect(external).toEqual([]);
  expect(writes).toEqual(['/v1/exceptions:fromBlockId', '/v1/auth/logout', '/v1/exceptions:fromBlockId', '/v1/auth/logout', '/v1/exceptions:fromBlockId']);
  fs.writeFileSync(path.join(output, 'browser-result.json'), JSON.stringify({ receipt, denied, errors, external, writes, mobile_form_bounds: box, scope: 'real local auth/API/PostgreSQL, seeded event store; replay queued, no replay worker/deploy/NGINX in browser fixture' }, null, 2) + '\n');
});

test('operator classifies through durable API; reload and read-only roles retain the receipt', async ({ page }) => {
  const password = process.env.STRATA_EXCEPTION_LAB_PASSWORD, output = process.env.STRATA_EXCEPTION_EVIDENCE_DIR;
  if (!password || !output) throw new Error('Isolated classification fixture required');
  const login = async (role: string) => {
    await page.getByTestId('login-username').fill(`example-${role}`);
    await page.getByTestId('login-password').fill(password);
    await page.getByTestId('password-login-btn').click();
    await expect(page.getByTestId('detail-block-id')).toBeVisible();
  };
  await page.goto('/#/events/STR-0000-0000-0000-0001'); await login('operator');
  await page.setViewportSize({ width: 390, height: 844 });
  await page.getByRole('button', { name: 'Mark false positive', exact: true }).click();
  await page.getByLabel('Classification reason').fill('example legitimate request');
  const write = page.waitForResponse((r) => r.url().endsWith(':markFalsePositive') && r.request().method() === 'POST');
  await page.getByRole('button', { name: 'Save classification', exact: true }).click();
  const response = await write; expect(response.status()).toBe(200);
  const receipt = await response.json();
  expect(receipt.false_positive).toBe(true); expect(receipt.etag).toBeTruthy();
  await expect(page.getByTestId('false-positive-saved')).toContainText('example legitimate request');
  await page.reload(); await expect(page.getByTestId('false-positive-saved')).toContainText('example-operator');
  await page.getByTestId('language-toggle-btn').click();
  await expect(page.getByTestId('false-positive-saved')).toContainText('Đã đánh dấu false positive');
  await page.screenshot({ path: path.join(output, 'classification-mobile-vi.png'), fullPage: true });
  const denied: Record<string, number> = {};
  for (const role of ['viewer', 'approver']) {
    await page.getByTestId('logout-btn').click(); await login(role);
    await expect(page.getByTestId('false-positive-saved')).toContainText('example legitimate request');
    await expect(page.getByRole('button', { name: 'Đánh dấu false positive', exact: true })).toHaveCount(0);
    denied[role] = await page.evaluate(async (etag) => {
      const session = JSON.parse(sessionStorage.getItem('strata.localSession') ?? '{}') as { token: string };
      return (await fetch('/v1/events/STR-0000-0000-0000-0001:markFalsePositive', { method: 'POST', headers: { Authorization: `Bearer ${session.token}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ reason: 'must be refused', etag, request_id: crypto.randomUUID() }) })).status;
    }, receipt.etag);
    expect(denied[role]).toBe(403);
  }
  fs.writeFileSync(path.join(output, 'classification-result.json'), JSON.stringify({ receipt, denied, scope: 'real local auth/API/PostgreSQL; seeded event; one durable classification, no deployment' }, null, 2) + '\n');
});
