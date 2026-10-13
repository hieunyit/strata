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

test.describe('Strata WAF - Security Events Management', () => {
  test.beforeEach(async ({ page }) => {
    await signedIn(page, ['operator']);
    await mockApi(page);
    await page.goto('/');
  });

  test('displays events table with accurate columns and badges', async ({ page }) => {
    await expect(page.getByRole('heading', { name: /Nhật ký Sự kiện Bảo mật|Security Events Log/i })).toBeVisible();

    // Check table rows
    const rows = page.getByTestId('event-row');
    await expect(rows).toHaveCount(3);

    // Verify first event details in table
    await expect(page.getByText('STR-8F3K-Q2VD-7XNM-A1PC')).toBeVisible();
    await expect(page.getByText('STR-3B9Y-K8P2-WM4C-9D0R')).toBeVisible();
    await expect(page.getByText('EVT-7X2W-5M1Q-9H8K-L0P4')).toBeVisible();
  });

  test('global Block ID lookup opens Decision Trace modal directly', async ({ page }) => {
    const searchInput = page.getByTestId('block-id-search-input');
    await searchInput.fill('STR-8F3K-Q2VD-7XNM-A1PC');

    const searchBtn = page.getByTestId('block-id-search-btn');
    await searchBtn.click();

    // Decision Trace modal opens
    const modal = page.getByTestId('decision-trace-modal');
    await expect(modal).toBeVisible();

    // Verify Decision Trace content
    await expect(modal.getByText('STR-8F3K-Q2VD-7XNM-A1PC')).toBeVisible();
    await expect(modal.getByText('45').first()).toBeVisible(); // SQLi or anomaly score
    await expect(modal.getByText('Rule 942100')).toBeVisible();
    await expect(modal.getByText('Rule 942150')).toBeVisible();
    await expect(modal.getByText("' OR 1=1 --")).toBeVisible();

    // Close modal
    const closeBtn = page.getByTestId('close-modal-btn');
    await closeBtn.click();
    await expect(modal).not.toBeVisible();
  });

  test('decision trace marks the violating field and credits the Sigma author', async ({ page }) => {
    await page.getByText('STR-8F3K-Q2VD-7XNM-A1PC').click();
    const modal = page.getByTestId('decision-trace-modal');
    await expect(modal).toBeVisible();
    await expect(modal.getByTestId('field-highlight').first()).toHaveText('body.query');
    await expect(modal.getByTestId('rule-meta').first()).toContainText('SQL Injection Attack Detected via libinjection');
    // only the Sigma rule has an author line
    await expect(modal.getByTestId('rule-author')).toHaveCount(1);
    await expect(modal.getByTestId('rule-author')).toContainText('A. Author (Example Org)');
    if (process.env.SCREENSHOT) {
      await modal.getByTestId('rule-author').scrollIntoViewIfNeeded();
      await modal.screenshot({ path: process.env.SCREENSHOT });
    }
  });

  test('masks IPs and snippets for a viewer, not for an operator', async ({ page, browser }) => {
    // This page is signed in as operator: full values.
    await page.getByText('STR-8F3K-Q2VD-7XNM-A1PC').click();
    await expect(page.getByTestId('modal-client-ip')).toHaveText('198.51.100.42');
    await expect(page.getByTestId('violation-snippet').first()).toHaveText("' OR 1=1 --");
    await expect(page.getByTestId('viewer-notice')).not.toBeVisible();

    // A second session signed in as viewer.
    const viewer = await browser.newPage();
    await signedIn(viewer, ['viewer'], 'lab-viewer');
    await mockApi(viewer);
    await viewer.goto('/');
    await expect(viewer.getByTestId('current-user')).toContainText('lab-viewer');
    await expect(viewer.getByTestId('table-client-ip').first()).toContainText('198.51.***.***');
    await viewer.getByText('STR-8F3K-Q2VD-7XNM-A1PC').click();
    await expect(viewer.getByTestId('modal-client-ip')).toHaveText('198.51.***.***');
    await expect(viewer.getByTestId('violation-snippet').first()).toHaveText('[REDACTED FOR VIEWER ROLE]');
    await expect(viewer.getByTestId('viewer-notice')).toBeVisible();
    await viewer.close();
  });

  test('shows the login page without a session', async ({ browser }) => {
    const anon = await browser.newPage();
    await anon.goto('/');
    await expect(anon.getByTestId('login-btn')).toBeVisible();
    await expect(anon.getByTestId('block-id-search-input')).not.toBeVisible();
    await anon.close();
  });

  test('filters events by action', async ({ page }) => {
    const actionSelect = page.getByTestId('action-filter-select');
    await actionSelect.selectOption('shadow');

    const applyBtn = page.getByTestId('apply-filters-btn');
    await applyBtn.click();

    // Only shadow event should remain
    const rows = page.getByTestId('event-row');
    await expect(rows).toHaveCount(1);
    await expect(page.getByText('EVT-7X2W-5M1Q-9H8K-L0P4')).toBeVisible();
  });

  test('filters events by client IP and time window', async ({ page }) => {
    const searches: Array<Record<string, unknown>> = [];
    page.on('request', (r) => {
      if (r.url().includes('/v1/events:search')) searches.push(r.postDataJSON() || {});
    });
    await page.getByTestId('client-ip-filter-input').fill('203.0.113');
    await page.getByTestId('time-preset-select').selectOption('1h');
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
    await page.route('**/v1/nodes', (route) =>
      route.fulfill({ contentType: 'application/json', body: JSON.stringify({ nodes: [
        { id: 'node-a', hostname: 'edge-01', group_id: 'lab', online: true },
        { id: 'node-b', hostname: 'edge-02', group_id: 'lab', online: false },
      ] }) }),
    );
    await page.route('**/v1/groups', (route) =>
      route.fulfill({ contentType: 'application/json', body: JSON.stringify({ groups: [{ id: 'lab', name: 'Lab' }] }) }),
    );
    await page.route('**/v1/rollouts', (route) =>
      route.fulfill({ contentType: 'application/json', body: JSON.stringify({ rollouts: [] }) }),
    );
    await page.route('**/v1/policies', (route) =>
      route.fulfill({ contentType: 'application/json', body: JSON.stringify({ policies: [
        { id: 'example-api', name: 'example-api', version: 2, spec: { mode: 'MODE_ENFORCE' } },
      ] }) }),
    );
    await page.getByTestId('nav-fleet').click();
    await expect(page.getByTestId('node-row')).toHaveCount(2);
    await expect(page.getByTestId('node-status').first()).toHaveText('Online');
    await page.getByTestId('nav-policies').click();
    await expect(page.getByTestId('policy-row')).toHaveCount(1);
    await expect(page.getByTestId('policy-version').first()).toHaveText('2');

    // The Block ID search on another page opens the trace on Events.
    await page.getByTestId('block-id-search-input').fill('STR-8F3K-Q2VD-7XNM-A1PC');
    await page.getByTestId('block-id-search-btn').click();
    await expect(page.getByTestId('decision-trace-modal')).toBeVisible();
    await expect(page.getByTestId('nav-events')).toHaveAttribute('aria-current', 'page');
  });

  test('switches language between Vietnamese and English', async ({ page }) => {
    const langBtn = page.getByTestId('language-toggle-btn');

    // Default is Vietnamese
    await expect(page.getByRole('heading', { name: 'Nhật ký Sự kiện Bảo mật' })).toBeVisible();

    // Switch to English
    await langBtn.click();
    await expect(page.getByRole('heading', { name: 'Security Events Log' })).toBeVisible();

    // Switch back to Vietnamese
    await langBtn.click();
    await expect(page.getByRole('heading', { name: 'Nhật ký Sự kiện Bảo mật' })).toBeVisible();
  });
});
