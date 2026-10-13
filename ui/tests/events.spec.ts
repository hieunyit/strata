import { test, expect, type Page } from '@playwright/test';
import { signedIn } from './session';

const mockEventsResponse = {
  events: [
    {
      block_id: 'STR-8F3K-Q2VD-7XNM-A1PC',
      timestamp: new Date().toISOString(),
      node_id: 'edge-worker-01',
      connector_type: 'nginx',
      policy_id: 'example-api',
      policy_version: 1,
      client_ip: '198.51.100.42',
      identity: 'anon-client-1',
      request_id: 'req-001',
      http_method: 'POST',
      http_host: 'api.example.test',
      http_path: '/v1/users/search',
      status_code: 403,
      action: 'block',
      score_protocol: 0,
      score_sqli: 45,
      score_xss: 0,
      score_anomaly: 45,
      matched_rules: [942100, 942150],
      violations: [
        {
          rule_id: 942100,
          layer: 'sqli',
          field: 'body.query',
          snippet: "' OR 1=1 --",
        },
        {
          rule_id: 942150,
          layer: 'sqli',
          field: 'body.query',
          snippet: "UNION SELECT null, username, password FROM users",
        },
      ],
      received_at: new Date().toISOString(),
    },
    {
      block_id: 'STR-3B9Y-K8P2-WM4C-9D0R',
      timestamp: new Date().toISOString(),
      node_id: 'edge-worker-02',
      connector_type: 'nginx',
      policy_id: 'example-api',
      policy_version: 1,
      client_ip: '203.0.113.19',
      identity: 'guest-browser',
      request_id: 'req-002',
      http_method: 'GET',
      http_host: 'api.example.test',
      http_path: '/comments',
      status_code: 403,
      action: 'block',
      score_protocol: 0,
      score_sqli: 0,
      score_xss: 30,
      score_anomaly: 30,
      matched_rules: [941100],
      violations: [
        {
          rule_id: 941100,
          layer: 'xss',
          field: 'uri.query.text',
          snippet: "<script>alert(document.cookie)</script>",
        },
      ],
      received_at: new Date().toISOString(),
    },
    {
      block_id: 'EVT-7X2W-5M1Q-9H8K-L0P4',
      timestamp: new Date().toISOString(),
      node_id: 'edge-worker-01',
      connector_type: 'nginx',
      policy_id: 'example-api',
      policy_version: 1,
      client_ip: '192.0.2.77',
      identity: 'scanner-bot',
      request_id: 'req-003',
      http_method: 'GET',
      http_host: 'api.example.test',
      http_path: '/.env',
      status_code: 200,
      action: 'shadow',
      score_protocol: 15,
      score_sqli: 0,
      score_xss: 0,
      score_anomaly: 15,
      matched_rules: [100005],
      violations: [
        {
          rule_id: 100005,
          layer: 'protocol',
          field: 'uri.path',
          snippet: "/.env",
        },
      ],
      received_at: new Date().toISOString(),
    }
  ],
  total_matched: 3,
};

// what GET /v1/events/{id} returns from the rule catalog (W09-F-01)
const mockRules = {
  '942100': { name: 'SQL Injection Attack Detected via libinjection', source: 'owasp-crs', license: 'Apache-2.0' },
  '942150': { name: 'Example Sigma rule on SQL keywords', source: 'sigma', author: 'A. Author (Example Org)', license: 'DRL-1.1' },
};

// GET /v1/stats/overview: 24 hourly buckets with a morning attack wave.
function mockOverview() {
  const now = Date.now() - (Date.now() % 3_600_000);
  const series = Array.from({ length: 24 }, (_, i) => {
    const wave = i > 14 && i < 19 ? 40 + i * 3 : 0;
    return {
      start: new Date(now - (23 - i) * 3_600_000).toISOString(),
      block: 4 + (i % 5) + wave,
      shadow: 2 + (i % 3) + Math.round(wave / 4),
      other: 1 + (i % 2),
    };
  });
  const sum = (k: 'block' | 'shadow' | 'other') => series.reduce((a, b) => a + b[k], 0);
  return {
    from: new Date(now - 23 * 3_600_000).toISOString(),
    to: new Date(now + 3_600_000).toISOString(),
    step_seconds: 3600,
    totals: { events: sum('block') + sum('shadow') + sum('other'), block: sum('block'), shadow: sum('shadow'), other: sum('other'), clients: 214, nodes: 2, policies: 2 },
    series,
    top_rules: [
      { rule_id: 942100, events: 212, block: 180, shadow: 32 },
      { rule_id: 941100, events: 141, block: 120, shadow: 21 },
      { rule_id: 930120, events: 66, block: 50, shadow: 16 },
      { rule_id: 913100, events: 41, block: 0, shadow: 41 },
    ],
    top_routes: [
      { policy_id: 'pilot-verify', host: 'api.example.test', path_prefix: '/v1/verify', events: 260, block: 230, shadow: 20 },
      { policy_id: 'pilot-upload', host: 'api.example.test', path_prefix: '/v1/upload', events: 120, block: 0, shadow: 110 },
      { policy_id: 'example-api', host: 'api.example.test', path_prefix: '/search', events: 48, block: 40, shadow: 4 },
    ],
    top_clients: [
      { client_ip: '203.0.113.19', events: 151, block: 140 },
      { client_ip: '198.51.100.42', events: 77, block: 60 },
    ],
    rules: {
      '942100': { name: 'SQL Injection Attack Detected via libinjection', source: 'owasp-crs' },
      '941100': { name: 'XSS Attack Detected via libinjection', source: 'owasp-crs' },
      '930120': { name: 'OS File Access Attempt', source: 'owasp-crs' },
      '913100': { name: 'Found User-Agent associated with security scanner', source: 'owasp-crs' },
    },
  };
}

async function mockApi(page: Page): Promise<void> {
    // Intercept API search requests
    await page.route('**/v1/events:search', async (route) => {
      const requestData = route.request().postDataJSON() || {};
      let filtered = [...mockEventsResponse.events];
      if (requestData.action) {
        filtered = filtered.filter(e => e.action === requestData.action);
      }
      if (requestData.client_ip) {
        filtered = filtered.filter(e => e.client_ip.includes(requestData.client_ip));
      }
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          events: filtered,
          total_matched: filtered.length,
        }),
      });
    });

    await page.route('**/v1/stats/overview*', (route) =>
      route.fulfill({ contentType: 'application/json', body: JSON.stringify(mockOverview()) }),
    );
    await page.route('**/v1/nodes', (route) =>
      route.fulfill({ contentType: 'application/json', body: JSON.stringify({ nodes: [
        { id: 'node-a', hostname: 'edge-01', group_id: 'lab', online: true },
        { id: 'node-b', hostname: 'edge-02', group_id: 'lab', online: false, last_seen_time: new Date(Date.now() - 900_000).toISOString() },
      ] }) }),
    );
    await page.route('**/v1/rollouts', (route) =>
      route.fulfill({ contentType: 'application/json', body: JSON.stringify({ rollouts: [] }) }),
    );
    await page.route('**/v1/policies', (route) =>
      route.fulfill({ contentType: 'application/json', body: JSON.stringify({ policies: [
        { id: 'example-api', name: 'example-api', version: 2, spec: { mode: 'MODE_ENFORCE' } },
      ] }) }),
    );

    // Intercept individual Block ID requests
    await page.route('**/v1/events/*', async (route) => {
      const url = route.request().url();
      const blockId = url.split('/v1/events/')[1]?.split('?')[0];
      const match = mockEventsResponse.events.find(e => e.block_id === blockId);
      if (match) {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ event: match, rules: mockRules }),
        });
      } else {
        await route.fulfill({
          status: 404,
          contentType: 'application/json',
          body: JSON.stringify({ error: 'event not found', block_id: blockId }),
        });
      }
    });

}

test.describe('Strata WAF console', () => {
  test.beforeEach(async ({ page }) => {
    await signedIn(page, ['operator']);
    await mockApi(page);
  });

  test('opens on the Overview, in English', async ({ page }) => {
    await page.goto('/');
    await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible();
    await expect(page.getByTestId('nav-overview')).toHaveAttribute('aria-current', 'page');
    await expect(page.getByTestId('top-rule')).toHaveCount(4);
    await expect(page.getByTestId('top-route').first()).toContainText('/v1/verify');
    await expect(page.getByTestId('strata-chart').locator('svg')).toBeVisible();
    await expect(page.getByTestId('kpi-nodes')).toContainText('1/2');
    if (process.env.SCREENSHOT_DIR) await page.screenshot({ path: `${process.env.SCREENSHOT_DIR}/overview.png`, fullPage: true });

    // a top rule opens its events
    await page.getByTestId('top-rule').first().getByRole('link').click();
    await expect(page).toHaveURL(/#\/events\?range=24h&rule_id=942100/);
    await expect(page.getByRole('heading', { name: 'Events' })).toBeVisible();
  });

  test('asks for 7 and 30 days', async ({ page }) => {
    const asked: string[] = [];
    page.on('request', (r) => r.url().includes('/v1/stats/overview') && asked.push(r.url()));
    await page.goto('/#/overview');
    await page.getByTestId('range-7d').click();
    await page.getByTestId('range-30d').click();
    await expect.poll(() => asked.length).toBeGreaterThanOrEqual(3);
    const span = (u: string) => {
      const q = new URL(u).searchParams;
      return Date.parse(q.get('to')!) - Date.parse(q.get('from')!);
    };
    expect(span(asked.at(-1)!)).toBe(30 * 24 * 3_600_000);
    expect(asked.some((u) => span(u) === 7 * 24 * 3_600_000)).toBe(true);
    await expect(page).toHaveURL(/range=30d/);
  });

  test('lists events, and a row opens its decision trace page', async ({ page }) => {
    await page.goto('/#/events');
    await expect(page.getByTestId('event-row')).toHaveCount(3);
    if (process.env.SCREENSHOT_DIR) await page.screenshot({ path: `${process.env.SCREENSHOT_DIR}/events.png`, fullPage: true });
    await page.getByTestId('event-row').first().click();
    await expect(page).toHaveURL(/#\/events\/STR-8F3K-Q2VD-7XNM-A1PC$/);
    const detail = page.getByTestId('event-detail');
    await expect(detail).toBeVisible();
    await expect(page.getByTestId('detail-block-id')).toHaveText('STR-8F3K-Q2VD-7XNM-A1PC');
    await expect(page.getByTestId('verdict-summary')).toContainText('Blocked by policy example-api');
    await expect(detail.getByText('Rule 942100', { exact: true })).toBeVisible();
    await expect(detail.getByText('Rule 942150', { exact: true })).toBeVisible();
    await expect(detail.getByTestId('field-highlight').first()).toHaveText('body.query');
    await expect(detail.getByTestId('rule-meta').first()).toContainText('SQL Injection Attack Detected via libinjection');
    // only the Sigma rule has an author line
    await expect(detail.getByTestId('rule-author')).toHaveCount(1);
    await expect(detail.getByTestId('rule-author')).toContainText('A. Author (Example Org)');
    if (process.env.SCREENSHOT_DIR) await page.screenshot({ path: `${process.env.SCREENSHOT_DIR}/event.png`, fullPage: true });
    await page.getByTestId('back-to-events').click();
    await expect(page.getByTestId('event-row')).toHaveCount(3);
  });

  test('the top bar Block ID lookup opens the event from any page', async ({ page }) => {
    await page.goto('/#/fleet');
    await page.getByTestId('block-id-search-input').fill('str-8f3k-q2vd-7xnm-a1pc');
    await page.getByTestId('block-id-search-btn').click();
    await expect(page.getByTestId('event-detail')).toBeVisible();
    await expect(page.getByTestId('nav-events')).toHaveAttribute('aria-current', 'page');
    await page.getByTestId('block-id-search-input').fill('STR-ZZZZ-ZZZZ-ZZZZ-ZZZZ');
    await page.getByTestId('block-id-search-btn').click();
    await expect(page.getByTestId('event-missing')).toContainText('No event with Block ID STR-ZZZZ-ZZZZ-ZZZZ-ZZZZ');
  });

  test('masks IPs and snippets for a viewer, not for an operator', async ({ page, browser }) => {
    await page.goto('/#/events/STR-8F3K-Q2VD-7XNM-A1PC');
    await expect(page.getByTestId('detail-client-ip')).toHaveText('198.51.100.42');
    await expect(page.getByTestId('violation-snippet').first()).toHaveText("' OR 1=1 --");
    await expect(page.getByTestId('viewer-notice')).not.toBeVisible();

    const viewer = await browser.newPage();
    await signedIn(viewer, ['viewer'], 'lab-viewer');
    await mockApi(viewer);
    await viewer.goto('/#/events');
    await expect(viewer.getByTestId('current-user')).toContainText('lab-viewer');
    await expect(viewer.getByTestId('table-client-ip').first()).toContainText('198.51.***.***');
    await viewer.getByText('STR-8F3K-Q2VD-7XNM-A1PC').click();
    await expect(viewer.getByTestId('detail-client-ip')).toHaveText('198.51.***.***');
    await expect(viewer.getByTestId('violation-snippet').first()).toHaveText('[REDACTED FOR VIEWER ROLE]');
    await expect(viewer.getByTestId('viewer-notice')).toBeVisible();
    await viewer.close();
  });

  test('shows the login page without a session', async ({ browser }) => {
    const anon = await browser.newPage();
    await anon.goto('/');
    await expect(anon.getByTestId('login-btn')).toBeVisible();
    await expect(anon.getByTestId('block-id-search-input')).not.toBeVisible();
    if (process.env.SCREENSHOT_DIR) await anon.screenshot({ path: `${process.env.SCREENSHOT_DIR}/login.png` });
    await anon.close();
  });

  test('filters events by verdict', async ({ page }) => {
    await page.goto('/#/events');
    await page.getByTestId('action-filter-select').selectOption('shadow');
    await page.getByTestId('apply-filters-btn').click();
    await expect(page.getByTestId('event-row')).toHaveCount(1);
    await expect(page.getByText('EVT-7X2W-5M1Q-9H8K-L0P4')).toBeVisible();
    await expect(page).toHaveURL(/action=shadow/);
  });

  test('filters events by client IP and time window', async ({ page }) => {
    const searches: Array<Record<string, unknown>> = [];
    page.on('request', (r) => {
      if (r.url().includes('/v1/events:search')) searches.push(r.postDataJSON() || {});
    });
    await page.goto('/#/events');
    await page.getByTestId('client-ip-filter-input').fill('203.0.113');
    await page.getByTestId('range-1h').click();
    const before = Date.now();
    await page.getByTestId('apply-filters-btn').click();

    await expect(page.getByTestId('event-row')).toHaveCount(1);
    await expect(page.getByText('STR-3B9Y-K8P2-WM4C-9D0R')).toBeVisible();
    const last = searches[searches.length - 1];
    expect(last.client_ip).toBe('203.0.113');
    const span = Date.parse(String(last.to)) - Date.parse(String(last.from));
    expect(span).toBe(60 * 60 * 1000);
    expect(Math.abs(Date.parse(String(last.to)) - before)).toBeLessThan(60 * 1000);
  });

  test('fleet and policies pages show the API data', async ({ page }) => {
    await page.route('**/v1/groups', (route) =>
      route.fulfill({ contentType: 'application/json', body: JSON.stringify({ groups: [{ id: 'lab', name: 'Lab' }] }) }),
    );
    await page.goto('/');
    await page.getByTestId('nav-fleet').click();
    await expect(page.getByTestId('node-row')).toHaveCount(2);
    await expect(page.getByTestId('node-status').first()).toHaveText('Online');
    await page.getByTestId('nav-policies').click();
    await expect(page.getByTestId('policy-row')).toHaveCount(1);
    await expect(page.getByTestId('policy-version').first()).toHaveText('2');
  });

  test('switches language to Vietnamese and back, and remembers it', async ({ page }) => {
    await page.goto('/#/events');
    await expect(page.getByRole('heading', { name: 'Events' })).toBeVisible();
    await page.getByTestId('language-toggle-btn').click();
    await expect(page.getByRole('heading', { name: 'Sự kiện' })).toBeVisible();
    await page.reload();
    await expect(page.getByRole('heading', { name: 'Sự kiện' })).toBeVisible();
    await page.getByTestId('language-toggle-btn').click();
    await expect(page.getByRole('heading', { name: 'Events' })).toBeVisible();
  });

  test('dark theme', async ({ page }) => {
    await page.goto('/');
    await page.getByTestId('theme-toggle-btn').click();
    await expect(page.locator('html')).toHaveClass(/dark/);
    await expect(page.getByTestId('top-rule')).toHaveCount(4);
    if (process.env.SCREENSHOT_DIR) await page.screenshot({ path: `${process.env.SCREENSHOT_DIR}/overview-dark.png`, fullPage: true });
  });

  test('works on a phone-sized screen', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto('/');
    await expect(page.getByTestId('kpi-events')).toBeVisible();
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    expect(overflow).toBeLessThanOrEqual(0);
    if (process.env.SCREENSHOT_DIR) await page.screenshot({ path: `${process.env.SCREENSHOT_DIR}/overview-phone.png`, fullPage: true });
  });
});
