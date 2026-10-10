import { test, expect, type Page } from '@playwright/test';
import { execFileSync } from 'child_process';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

// W03-F-01 and W06-F-01 on the lab: sign in and out through Keycloak, find an
// event by Block ID and read its decision trace, masked for a viewer.

const here = path.dirname(fileURLToPath(import.meta.url));
const lab = path.resolve(here, '../../deploy/lab');
const env = Object.fromEntries(
  fs.readFileSync(path.join(lab, '.state/env'), 'utf8')
    .split('\n')
    .filter((l) => l.includes('='))
    .map((l) => [l.slice(0, l.indexOf('=')), l.slice(l.indexOf('=') + 1)]),
);

// emitEvent sends one event into agent-1's event socket (strata-emit stands
// in for the NGINX worker until W07-N-01) and returns its Block ID.
function emitEvent(): string {
  const out = execFileSync('docker', [
    'compose', '-f', path.join(lab, 'compose.yaml'), '--env-file', path.join(lab, '.state/env'),
    'exec', '-T', 'agent-1', 'strata-emit', '-event-socket', 'unix:/run/strata/events.sock',
  ]).toString().trim();
  expect(out).toMatch(/^STR-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}$/);
  return out;
}

async function signIn(page: Page, user: string): Promise<void> {
  await page.goto('/');
  await page.getByTestId('login-btn').click();
  await page.locator('#username').fill(user);
  await page.locator('#password').fill(env[`LAB_${user.replace('lab-', '').toUpperCase()}_PASSWORD`]);
  await page.locator('#kc-login').click();
  await expect(page.getByTestId('current-user')).toContainText(user);
}

async function openTrace(page: Page, blockId: string): Promise<void> {
  // The event reaches ClickHouse after the agent's next push and flush.
  await expect(async () => {
    await page.getByTestId('block-id-search-input').fill(blockId);
    await page.getByTestId('block-id-search-btn').click();
    await expect(page.getByTestId('decision-trace-modal').getByText(blockId)).toBeVisible({ timeout: 2000 });
  }).toPass({ timeout: 30_000 });
}

test('operator signs in, reads a full decision trace, and signs out', async ({ page }) => {
  const id = emitEvent();
  await signIn(page, 'lab-operator');
  await expect(page.getByTestId('current-role')).toContainText('Operator');
  await expect(page.getByTestId('cp-version')).toBeVisible();

  await openTrace(page, id);
  await expect(page.getByTestId('modal-client-ip')).toHaveText('192.0.2.10');
  await expect(page.getByTestId('violation-snippet').first()).toHaveText('/%2e%2e/');
  await page.getByTestId('modal-close-btn').click();

  await page.getByTestId('logout-btn').click();
  await expect(page.getByTestId('login-btn')).toBeVisible();
  // Signed out at Keycloak too: signing in asks for the password again.
  await page.getByTestId('login-btn').click();
  await expect(page.locator('#username')).toBeVisible();
});

test('viewer sees the trace with the IP and snippet masked by the API', async ({ page }) => {
  const id = emitEvent();
  await signIn(page, 'lab-viewer');
  await openTrace(page, id);
  await expect(page.getByTestId('modal-client-ip')).not.toHaveText('192.0.2.10');
  await expect(page.getByTestId('modal-client-ip')).toContainText('192.0.');
  await expect(page.getByTestId('violation-snippet').first()).not.toHaveText('/%2e%2e/');
  await expect(page.getByTestId('viewer-notice')).toBeVisible();
});
