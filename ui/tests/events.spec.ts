import { test, expect } from '@playwright/test';

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

test.describe('Strata WAF - Security Events Management', () => {
  test.beforeEach(async ({ page }) => {
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
          body: JSON.stringify({ event: match }),
        });
      } else {
        await route.fulfill({
          status: 404,
          contentType: 'application/json',
          body: JSON.stringify({ error: 'event not found', block_id: blockId }),
        });
      }
    });

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

  test('enforces RBAC masking for viewer role', async ({ page }) => {
    // Switch role to Viewer
    const roleSelect = page.getByTestId('role-select');
    await roleSelect.selectOption('viewer');

    // Table IP should be masked
    const ips = page.getByTestId('table-client-ip');
    await expect(ips.first()).toContainText('198.51.***.***');

    // Open detail modal
    await page.getByText('STR-8F3K-Q2VD-7XNM-A1PC').click();
    const modal = page.getByTestId('decision-trace-modal');
    await expect(modal).toBeVisible();

    // IP in modal masked
    const modalIp = page.getByTestId('modal-client-ip');
    await expect(modalIp).toHaveText('198.51.***.***');

    // Snippet in modal redacted
    const snippets = page.getByTestId('violation-snippet');
    await expect(snippets.first()).toHaveText('[REDACTED FOR VIEWER ROLE]');

    // Viewer notice visible
    await expect(page.getByTestId('viewer-notice')).toBeVisible();

    // Action buttons must NOT exist
    await expect(page.getByTestId('action-mark-fp')).not.toBeVisible();
    await expect(page.getByTestId('action-create-exception')).not.toBeVisible();
    await expect(page.getByTestId('action-block-ip')).not.toBeVisible();

    // Switch back to Operator
    await roleSelect.selectOption('operator');
    await expect(modalIp).toHaveText('198.51.100.42');
    await expect(snippets.first()).toHaveText("' OR 1=1 --");
    await expect(page.getByTestId('action-mark-fp')).toBeVisible();
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
