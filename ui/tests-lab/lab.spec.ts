import { test, expect, type Page, type APIRequestContext } from '@playwright/test';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

// W03-F-01 and W06-F-01 on the lab: sign in and out through Keycloak, find an
// event by Block ID and read its decision trace, masked for a viewer.
// W07-F-01: a deploy, seen node by node on the Fleet page.

const here = path.dirname(fileURLToPath(import.meta.url));
const lab = path.resolve(here, '../../deploy/lab');
const env = Object.fromEntries(
  fs.readFileSync(path.join(lab, '.state/env'), 'utf8')
    .split('\n')
    .filter((l) => l.includes('='))
    .map((l) => [l.slice(0, l.indexOf('=')), l.slice(l.indexOf('=') + 1)]),
);

// blocked sends a NUL byte in the query to NGINX (node-1, rule 100013) and
// returns the Block ID it answers with: the event goes worker -> agent ->
// control plane. (Not %2e%2e: the client resolves it as a dot segment.)
async function blocked(request: APIRequestContext): Promise<string> {
  const res = await request.get('http://127.0.0.1:18080/v1/items?id=1%00', {
    headers: { Host: 'api.example.test', Accept: 'application/json' }, maxRedirects: 0,
  });
  expect(res.status()).toBe(403);
  const id = res.headers()['x-strata-block-id'];
  expect(id).toMatch(/^STR-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}$/);
  return id;
}

async function token(request: APIRequestContext, user: string): Promise<string> {
  const res = await request.post('http://127.0.0.1:18180/realms/strata/protocol/openid-connect/token', {
    form: { grant_type: 'password', client_id: 'strata-lab-cli', client_secret: env.LAB_CLI_SECRET, username: user,
      password: env[`LAB_${user.replace('lab-', '').toUpperCase()}_PASSWORD`] },
  });
  return (await res.json()).access_token as string;
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
    await expect(page.getByTestId('event-detail')).toBeVisible({ timeout: 2000 });
    await expect(page.getByTestId('detail-block-id')).toHaveText(blockId);
  }).toPass({ timeout: 30_000 });
}

test('operator signs in, reads a full decision trace, and signs out', async ({ page, request }) => {
  const id = await blocked(request);
  await signIn(page, 'lab-operator');
  await expect(page.getByTestId('current-role')).toContainText('Operator');
  await expect(page.getByTestId('cp-version')).toBeVisible();

  await openTrace(page, id);
  await expect(page.getByTestId('detail-client-ip')).toHaveText(/^\d+\.\d+\.\d+\.\d+$/);

  await page.getByTestId('logout-btn').click();
  await expect(page.getByTestId('login-btn')).toBeVisible();
  // Signed out at Keycloak too: signing in asks for the password again.
  await page.getByTestId('login-btn').click();
  await expect(page.locator('#username')).toBeVisible();
});

test('viewer sees the trace with the IP masked by the API', async ({ page, request }) => {
  const id = await blocked(request);
  await signIn(page, 'lab-viewer');
  await openTrace(page, id);
  await expect(page.getByTestId('detail-client-ip')).toHaveText(/^\d+\.\d+\.\d+\.0\/24$/);
  await expect(page.getByTestId('viewer-notice')).toBeVisible();
});

// W04-F-01 on the lab: the Fleet page shows both enrolled agents online,
// and the Policies page shows a policy created through the API with its
// version history.
test('fleet and policies pages show the lab data', async ({ page, request }) => {
  const id = `ui-${Date.now()}`;
  const headers = { Authorization: `Bearer ${await token(request, 'lab-operator')}` };
  const created = await request.post('http://127.0.0.1:18090/v1/policies', { headers, data: { id, name: id, spec: { mode: 'MODE_SHADOW' } } });
  expect(created.status()).toBe(200);
  const etag = (await created.json()).policy.etag as string;
  expect((await request.patch(`http://127.0.0.1:18090/v1/policies/${id}`, { headers, data: { etag, spec: { mode: 'MODE_ENFORCE' } } })).status()).toBe(200);

  await signIn(page, 'lab-viewer');
  await page.getByTestId('nav-fleet').click();
  await expect(page.locator('[data-testid="node-row"][data-status="online"]')).toHaveCount(2, { timeout: 15_000 });

  await page.getByTestId('nav-policies').click();
  const row = page.getByTestId('policy-row').filter({ hasText: id });
  await expect(row).toContainText('Enforce');
  await row.click();
  await expect(page.getByTestId('policy-version-row')).toHaveCount(2);
});

// W07-F-01: deploy a policy on the lab and watch each node move through
// the rollout on the Fleet page; a screenshot at every change of state
// (STRATA_LAB_SHOTS, default docs/reports/w07-f-01).
test('a deploy shows node by node on the Fleet page', async ({ page, request }) => {
  test.setTimeout(120_000);
  const shots = process.env.STRATA_LAB_SHOTS ?? path.resolve(here, '../../docs/reports/w07-f-01');
  fs.mkdirSync(shots, { recursive: true });
  await signIn(page, 'lab-viewer');
  await page.getByTestId('nav-fleet').click();
  await expect(page.locator('[data-testid="node-row"][data-status="online"]')).toHaveCount(2, { timeout: 15_000 });
  // revoked nodes (packaging tests, W10-N-01) stay listed: read the online ones
  const online = page.locator('[data-testid="node-row"][data-status="online"]');
  await expect(online.locator('[data-testid="node-nginx"]').first()).toHaveText(/^1\.3\d\.\d+$/, { timeout: 15_000 });
  const before = Number((await online.locator('[data-testid="node-bundle"]').first().textContent())?.replace('v', ''));
  await page.screenshot({ path: path.join(shots, '0-before.png'), fullPage: true });

  // example-web to enforce and deploy, through the API as an operator
  const headers = { Authorization: `Bearer ${await token(request, 'lab-operator')}` };
  const api = 'http://127.0.0.1:18090/v1/policies/example-web';
  const deploy = async (mode: string) => {
    const p = await (await request.get(api, { headers })).json();
    expect((await request.patch(api, { headers, data: { etag: p.policy.etag, spec: { ...p.policy.spec, mode } } })).status()).toBe(200);
    const d = await request.post(`${api}:deploy`, { headers, data: {} });
    expect(d.status()).toBe(200);
    return (await d.json()).bundle.version as string;
  };
  const version = await deploy('MODE_ENFORCE');
  expect(Number(version)).toBeGreaterThan(before);

  // every distinct picture of the rollout and the nodes, until both run it
  const seen = new Set<string>();
  let n = 0;
  const deadline = Date.now() + 60_000;
  for (;;) {
    const states = await page.evaluate(() => {
      const r = document.querySelector('[data-testid="rollout"]');
      const nodes = [...document.querySelectorAll('[data-testid="rollout-node"]')].map((e) => `${e.getAttribute('data-node')}=${e.getAttribute('data-state')}`);
      const rows = [...document.querySelectorAll('[data-testid="node-row"]')].map((e) =>
        `${e.getAttribute('data-node')}:${e.querySelector('[data-testid="node-bundle"]')?.textContent}:${e.querySelector('[data-testid="node-bundle-state"]')?.getAttribute('data-state')}`);
      return `${r?.getAttribute('data-state') ?? 'none'} ${nodes.join(',')} | ${rows.join(',')}`;
    });
    if (!seen.has(states)) {
      seen.add(states);
      n++;
      fs.appendFileSync(path.join(shots, 'steps.txt'), `${n} ${new Date().toISOString()} ${states}\n`);
      await page.screenshot({ path: path.join(shots, `${n}-step.png`), fullPage: true });
    }
    const all = await online.evaluateAll((es, v) => es.every((e) =>
      e.querySelector('[data-testid="node-bundle"]')?.textContent === `v${v}` &&
      e.querySelector('[data-testid="node-bundle-state"]')?.getAttribute('data-state') === 'ACTIVE'), version);
    if (all || Date.now() > deadline) {
      expect(all).toBe(true);
      break;
    }
    await page.waitForTimeout(250);
  }
  expect(n).toBeGreaterThanOrEqual(3); // before the nodes move, one after the other, done
  await deploy('MODE_SHADOW');
});

