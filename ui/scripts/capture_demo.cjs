const http = require('http');
const fs = require('fs');
const path = require('path');
const { chromium } = require('playwright-core');

const DIST_DIR = path.join(__dirname, '../dist');
const OUTPUT_DIR = process.argv[2] || path.join(__dirname, '../../docs/reports/screenshots');

if (!fs.existsSync(OUTPUT_DIR)) {
  fs.mkdirSync(OUTPUT_DIR, { recursive: true });
}

// 1. Static file server for /ui/dist
const mimeTypes = {
  '.html': 'text/html',
  '.js': 'text/javascript',
  '.css': 'text/css',
  '.json': 'application/json',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
};

const server = http.createServer((req, res) => {
  let reqPath = req.url.split('?')[0];
  if (reqPath === '/' || !path.extname(reqPath)) {
    reqPath = '/index.html';
  }
  const filePath = path.join(DIST_DIR, reqPath);
  if (fs.existsSync(filePath)) {
    const ext = path.extname(filePath);
    res.writeHead(200, { 'Content-Type': mimeTypes[ext] || 'application/octet-stream' });
    fs.createReadStream(filePath).pipe(res);
  } else {
    // SPA fallback
    res.writeHead(200, { 'Content-Type': 'text/html' });
    fs.createReadStream(path.join(DIST_DIR, 'index.html')).pipe(res);
  }
});

const mockApi = {
  '/v1/auth/me': { username: 'soc_admin', roles: ['admin', 'operator'] },
  '/v1/auth/methods': { local: true, oidc: false },
  '/v1/version': { version: '0.13.0', commit: '82bc603', api_version: 'v1' },
  '/v1/policies': {
    policies: [
      { id: 'example-api', name: 'Core Banking API', version: 1, state: 'ENFORCE' },
      { id: 'partner-gw', name: 'Partner Gateway', version: 2, state: 'SHADOW' }
    ]
  },
  '/v1/groups': {
    groups: [
      { id: 'prod-edge', name: 'Production Edge Clusters' }
    ]
  },
  '/v1/nodes': {
    nodes: [
      { id: 'edge-hcm-01', hostname: 'edge-hcm-01.prod.internal', ip: '10.0.1.20', status: 'ONLINE', group_id: 'prod-edge', policy_id: 'example-api', policy_version: 1, last_heartbeat: '2026-10-16T15:10:00Z', proxy_version: '1.25.4', module_version: '0.13.0', bundle_version: 1, bundle_state: 'ACTIVE' },
      { id: 'edge-hn-02', hostname: 'edge-hn-02.prod.internal', ip: '10.0.2.22', status: 'ONLINE', group_id: 'prod-edge', policy_id: 'example-api', policy_version: 1, last_heartbeat: '2026-10-16T15:10:00Z', proxy_version: '1.25.4', module_version: '0.13.0', bundle_version: 1, bundle_state: 'ACTIVE' }
    ]
  },
  '/v1/rollouts': { rollouts: [] },
  '/v1/stats/overview': {
    from: '2026-10-16T08:00:00Z',
    to: '2026-10-16T16:00:00Z',
    step_seconds: 3600,
    totals: { events: 128450, block: 3420, shadow: 850, pass: 124150, error: 30, clients: 1120, nodes: 2, policies: 2 },
    series: [
      { start: '2026-10-16T08:00:00Z', time: '2026-10-16T08:00:00Z', block: 120, shadow: 40, pass: 4500, error: 2 },
      { start: '2026-10-16T09:00:00Z', time: '2026-10-16T09:00:00Z', block: 340, shadow: 80, pass: 7200, error: 1 },
      { start: '2026-10-16T10:00:00Z', time: '2026-10-16T10:00:00Z', block: 520, shadow: 110, pass: 8900, error: 5 },
      { start: '2026-10-16T11:00:00Z', time: '2026-10-16T11:00:00Z', block: 410, shadow: 95, pass: 8100, error: 0 },
      { start: '2026-10-16T12:00:00Z', time: '2026-10-16T12:00:00Z', block: 290, shadow: 60, pass: 6500, error: 1 },
      { start: '2026-10-16T13:00:00Z', time: '2026-10-16T13:00:00Z', block: 480, shadow: 130, pass: 9400, error: 3 },
      { start: '2026-10-16T14:00:00Z', time: '2026-10-16T14:00:00Z', block: 620, shadow: 150, pass: 10200, error: 8 },
      { start: '2026-10-16T15:00:00Z', time: '2026-10-16T15:00:00Z', block: 640, shadow: 185, pass: 11200, error: 10 }
    ],
    top_rules: [
      { rule_id: 942100, events: 1840, block: 1800, shadow: 40 },
      { rule_id: 941100, events: 920, block: 850, shadow: 70 },
      { rule_id: 920100, events: 480, block: 460, shadow: 20 },
      { rule_id: 700001, events: 180, block: 180, shadow: 0 }
    ],
    top_routes: [
      { policy_id: 'example-api', host: 'api.example.test', path_prefix: '/v1/users', events: 1420, block: 1200, shadow: 200, error: 20 },
      { policy_id: 'example-api', host: 'api.example.test', path_prefix: '/v1/auth', events: 890, block: 700, shadow: 180, error: 10 },
      { policy_id: 'partner-gw', host: 'partner.example.test', path_prefix: '/webhooks', events: 640, block: 120, shadow: 520, error: 0 }
    ],
    rules: {
      '942100': { name: 'SQL Injection Probe: libinjection detected', severity: 'critical', description: 'Detects SQL injection using libinjection token classification' },
      '941100': { name: 'XSS Probe: Script tag injection', severity: 'high', description: 'Detects HTML script injection in query/body' },
      '920100': { name: 'HTTP Protocol Violation: Missing User-Agent', severity: 'medium', description: 'Detects requests without User-Agent header' },
      '700001': { name: 'Virtual Patch: CVE-2024-21733 Webhook RCE', severity: 'critical', description: 'Virtual patch preventing remote code execution' }
    },
    top_clients: [
      { client_ip: '198.51.100.42', events: 1120, block: 1100 },
      { client_ip: '203.0.113.15', events: 780, block: 700 }
    ],
    inspection: []
  },
  '/v1/stats/geo': {
    from: '2026-10-15T08:00:00Z',
    to: '2026-10-16T16:00:00Z',
    countries: [
      { country_iso: 'VN', events: 48200, blocked: 120, top_attack_type: 'SQLi probe' },
      { country_iso: 'US', events: 32100, blocked: 1420, top_attack_type: 'XSS Script Tag' },
      { country_iso: 'SG', events: 18400, blocked: 310, top_attack_type: 'Path Traversal' },
      { country_iso: 'DE', events: 9200, blocked: 840, top_attack_type: 'RCE Webhook' },
      { country_iso: 'JP', events: 6400, blocked: 210, top_attack_type: 'Scanner Bot' },
      { country_iso: 'CN', events: 5100, blocked: 450, top_attack_type: 'Credential Stuffing' },
      { country_iso: 'GB', events: 4200, blocked: 380, top_attack_type: 'Remote File Inclusion' },
      { country_iso: 'FR', events: 3800, blocked: 290, top_attack_type: 'SSRF Probe' },
      { country_iso: 'IN', events: 3100, blocked: 180, top_attack_type: 'Crawler Scanner' }
    ],
    asns: [
      { asn: 7552, as_org: 'Viettel Group', events: 24500, blocked: 60 },
      { asn: 13335, as_org: 'Cloudflare Inc.', events: 18200, blocked: 450 },
      { asn: 16509, as_org: 'Amazon.com Inc.', events: 14100, blocked: 890 },
      { asn: 15169, as_org: 'Google LLC', events: 11300, blocked: 110 }
    ],
    grid: [
      { geohash: 'w4g', lat: 10.8231, lon: 106.6297, city: 'Ho Chi Minh City', country_iso: 'VN', events: 28400, blocked: 80, top_attack_type: 'SQLi' },
      { geohash: 'w7e', lat: 21.0285, lon: 105.8542, city: 'Hanoi', country_iso: 'VN', events: 19800, blocked: 40, top_attack_type: 'XSS' }
    ]
  },
  '/v1/stats/timeline': {
    from: '2026-10-15T16:00:00Z',
    to: '2026-10-16T16:00:00Z',
    step: '1h',
    buckets: [
      { timestamp: '2026-10-16T08:00:00Z', total: 6400, blocked: 280, monitored: 80, passed: 6040 },
      { timestamp: '2026-10-16T09:00:00Z', total: 7200, blocked: 310, monitored: 90, passed: 6800 },
      { timestamp: '2026-10-16T10:00:00Z', total: 8500, blocked: 420, monitored: 110, passed: 7970 },
      { timestamp: '2026-10-16T11:00:00Z', total: 9100, blocked: 510, monitored: 130, passed: 8460 },
      { timestamp: '2026-10-16T12:00:00Z', total: 8800, blocked: 390, monitored: 95, passed: 8315 },
      { timestamp: '2026-10-16T13:00:00Z', total: 10010, blocked: 480, monitored: 130, passed: 9400 },
      { timestamp: '2026-10-16T14:00:00Z', total: 10970, blocked: 620, monitored: 150, passed: 10200 },
      { timestamp: '2026-10-16T15:00:00Z', total: 12025, blocked: 640, monitored: 185, passed: 11200 }
    ]
  },
  '/v1/events:search': {
    events: [
      {
        block_id: 'STR-8F3K-Q2VD-7XNM-A1PC',
        timestamp: '2026-10-16T15:12:45Z',
        node_id: 'edge-hcm-01',
        connector_type: 'nginx',
        policy_id: 'example-api',
        policy_version: 1,
        client_ip: '198.51.100.42',
        identity: 'sec-scanner-bot',
        request_id: 'req-98fa-1234',
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
          { rule_id: 942100, layer: 'sqli', field: 'body.query', snippet: "' UNION SELECT username, password_hash FROM admin_users --" }
        ],
        received_at: '2026-10-16T15:12:46Z',
        user_agent: 'Mozilla/5.0 (compatible; SecurityAudit/3.2)'
      },
      {
        block_id: 'STR-9C2M-X4TY-8BKL-P9WR',
        timestamp: '2026-10-16T15:10:12Z',
        node_id: 'edge-hn-02',
        connector_type: 'nginx',
        policy_id: 'partner-gw',
        policy_version: 2,
        client_ip: '203.0.113.88',
        identity: 'partner-app',
        request_id: 'req-77cc-55aa',
        http_method: 'GET',
        http_host: 'partner.example.test',
        http_path: '/webhooks/receive?sig=valid&payload=<script>alert(1)</script>',
        status_code: 200,
        action: 'shadow',
        score_protocol: 0,
        score_sqli: 0,
        score_xss: 30,
        score_anomaly: 30,
        matched_rules: [941100],
        violations: [
          { rule_id: 941100, layer: 'xss', field: 'uri.query.payload', snippet: '<script>alert(1)</script>' }
        ],
        received_at: '2026-10-16T15:10:13Z'
      },
      {
        block_id: 'STR-1A4D-7N8P-3KQW-9M2Z',
        timestamp: '2026-10-16T15:08:01Z',
        node_id: 'edge-hcm-01',
        connector_type: 'nginx',
        policy_id: 'example-api',
        policy_version: 1,
        client_ip: '192.0.2.14',
        http_method: 'GET',
        http_host: 'api.example.test',
        http_path: '/v1/healthz',
        status_code: 200,
        action: 'pass',
        score_protocol: 0,
        score_sqli: 0,
        score_xss: 0,
        score_anomaly: 0,
        received_at: '2026-10-16T15:08:02Z'
      }
    ],
    total_matched: 128450,
    next_page_token: 'token-page-2'
  },
  '/v1/events/STR-8F3K-Q2VD-7XNM-A1PC': {
    event: {
      block_id: 'STR-8F3K-Q2VD-7XNM-A1PC',
      timestamp: '2026-10-16T15:12:45Z',
      node_id: 'edge-hcm-01',
      connector_type: 'nginx',
      policy_id: 'example-api',
      policy_version: 1,
      client_ip: '198.51.100.42',
      identity: 'sec-scanner-bot',
      request_id: 'req-98fa-1234',
      http_method: 'POST',
      http_host: 'api.example.test',
      http_path: '/v1/users/search',
      status_code: 403,
      action: 'block',
      score_protocol: 0,
      score_sqli: 45,
      score_xss: 0,
      score_anomaly: 45,
      inspection: 'partial',
      matched_rules: [942100, 942150],
      violations: [
        { rule_id: 942100, layer: 'sqli', field: 'body.query', snippet: "' UNION SELECT username, password_hash FROM admin_users --" }
      ],
      headers: [
        { name: 'Host', value: 'api.example.test' },
        { name: 'User-Agent', value: 'Mozilla/5.0 (compatible; SecurityAudit/3.2)' },
        { name: 'Content-Type', value: 'application/json' },
        { name: 'Authorization', value: '[REDACTED]' },
        { name: 'X-Request-ID', value: 'req-98fa-1234' }
      ],
      received_at: '2026-10-16T15:12:46Z',
      user_agent: 'Mozilla/5.0 (compatible; SecurityAudit/3.2)'
    },
    rules: {
      '942100': { name: 'SQL Injection Probe: libinjection detected', severity: 'critical', description: 'Detects SQL injection using libinjection token classification' },
      '942150': { name: 'SQL Injection: tautology or union statement', severity: 'high', description: 'Detects high-risk SQL keywords in request payload' }
    }
  },
  '/v1/audit': {
    entries: [
      {
        id: 'aud-101',
        at: '2026-10-16T15:05:00Z',
        actor: 'admin@strata.internal',
        channel: 'REST',
        action: 'RevokeNode',
        resource: 'edge-worker-old-03',
        before: { node_id: 'edge-worker-old-03', status: 'ONLINE', ip: '10.0.1.99' },
        after: { node_id: 'edge-worker-old-03', status: 'REVOKED', revoked_at: '2026-10-16T15:05:00Z' }
      },
      {
        id: 'aud-102',
        at: '2026-10-16T14:40:00Z',
        actor: 'secops_lead',
        channel: 'REST',
        action: 'UpdatePolicy',
        resource: 'example-api v2',
        before: { policy_id: 'example-api', version: 1, mode: 'shadow' },
        after: { policy_id: 'example-api', version: 2, mode: 'enforce' }
      },
      {
        id: 'aud-103',
        at: '2026-10-16T14:15:00Z',
        actor: 'admin@strata.internal',
        channel: 'REST',
        action: 'AddException',
        resource: 'STR-8F3K-Q2VD-7XNM-A1PC',
        before: null,
        after: { rule_id: 920100, path: '/v1/healthz', ttl_seconds: 86400 }
      }
    ]
  },
  '/v1/users': {
    users: [
      { username: 'admin', roles: ['admin', 'operator', 'approver'], disabled: false, locked: false, last_login_at: '2026-10-16T15:10:00Z' },
      { username: 'secops_lead', roles: ['operator', 'approver'], disabled: false, locked: false, last_login_at: '2026-10-16T14:30:00Z' },
      { username: 'auditor', roles: ['viewer'], disabled: false, locked: false, last_login_at: '2026-10-16T11:00:00Z' }
    ]
  },
  '/v1/service-accounts': {
    service_accounts: [
      { id: 'sa-cicd-deployer', name: 'CI/CD Deployer Bot', description: 'GitHub Actions policy deployment pipeline', roles: ['operator', 'approver'], created_at: '2026-10-01T08:00:00Z' },
      { id: 'sa-siem-exporter', name: 'SIEM Exporter Agent', description: 'Splunk/Datadog security events harvester', roles: ['viewer'], created_at: '2026-10-05T09:30:00Z' }
    ]
  }
};

server.listen(5173, async () => {
  console.log('Static preview server running on http://127.0.0.1:5173');
  try {
    const browser = await chromium.launch({
      executablePath: '/ms-playwright/chromium-1248/chrome-linux64/chrome',
      args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-gpu']
    });

    const context = await browser.newContext({
      viewport: { width: 1440, height: 900 }
    });

    const page = await context.newPage();

    // Route interception for /v1 APIs
    await page.route('**/v1/**', async (route) => {
      const url = new URL(route.request().url());
      const pathKey = url.pathname;
      let matched = mockApi[pathKey];
      if (!matched) {
        for (const [k, v] of Object.entries(mockApi)) {
          if (pathKey.startsWith(k)) {
            matched = v;
            break;
          }
        }
      }
      if (matched) {
        return route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(matched)
        });
      }
      return route.fulfill({ status: 200, contentType: 'application/json', body: '{}' });
    });

    // Set auth session in sessionStorage before navigation
    await page.addInitScript(() => {
      window.sessionStorage.setItem('strata.localSession', JSON.stringify({
        token: 'stl_admin_session_token',
        username: 'soc_admin',
        roles: ['admin', 'operator'],
        expires_at: new Date(Date.now() + 86400000).toISOString(),
      }));
      window.localStorage.setItem('i18nextLng', 'vi'); // display Vietnamese UI
    });

    page.on('console', (msg) => console.log('BROWSER_LOG:', msg.text()));
    page.on('pageerror', (err) => console.log('BROWSER_ERR:', err.message));
    page.on('requestfailed', (req) => console.log('REQ_FAIL:', req.url(), req.failure()?.errorText));

    // 1. Overview Page
    console.log('Capturing 01_overview.png and map captures...');
    await page.goto('http://127.0.0.1:5173/#/overview');
    await page.waitForTimeout(2500);
    // Viewport screenshot (contains Bento KPIs + Threat Intelligence Map above the fold)
    await page.screenshot({ path: path.join(OUTPUT_DIR, '01_overview.png') });
    // Full page screenshot (entire dashboard top to bottom)
    await page.screenshot({ fullPage: true, path: path.join(OUTPUT_DIR, '01_overview_full.png') });
    // Dedicated Threat Intelligence Map screenshot
    const mapLocator = page.locator('[data-testid="geomap-container"]');
    if (await mapLocator.isVisible()) {
      await mapLocator.screenshot({ path: path.join(OUTPUT_DIR, '01_threat_intelligence_map.png') });
    }

    // 2. Events Page
    console.log('Capturing 02_events_list.png...');
    await page.locator('[data-testid="nav-events"]').click();
    await page.waitForSelector('[data-testid="event-row"]');
    await page.waitForTimeout(600);
    await page.screenshot({ path: path.join(OUTPUT_DIR, '02_events_list.png') });

    // 3. Events Page (Historical Page 2 - Live Paused Banner)
    console.log('Capturing 03_events_live_paused.png...');
    const nextBtn = page.locator('[data-testid="next-page-btn"]');
    if (await nextBtn.isVisible() && !(await nextBtn.isDisabled())) {
      await nextBtn.click();
      await page.waitForSelector('[data-testid="live-paused-banner"]');
      await page.waitForTimeout(500);
      await page.screenshot({ path: path.join(OUTPUT_DIR, '03_events_live_paused.png') });
    }

    // Return to Page 1
    const returnBtn = page.locator('[data-testid="return-page-1-btn"]');
    if (await returnBtn.isVisible()) {
      await returnBtn.click();
      await page.waitForTimeout(400);
    }

    // 4. Event Detail Page (Copy as cURL & Truncation Notice)
    console.log('Capturing 04_event_detail_curl.png...');
    await page.locator('[data-testid="event-row"]').first().click();
    await page.waitForSelector('[data-testid="copy-curl-btn"]');
    await page.waitForSelector('[data-testid="truncation-notice"]');
    await page.waitForTimeout(600);
    await page.screenshot({ path: path.join(OUTPUT_DIR, '04_event_detail_curl.png') });

    // 5. Fleet Page & Destructive Modal
    console.log('Capturing 05_fleet_destructive_modal.png...');
    await page.locator('[data-testid="nav-fleet"]').click();
    await page.waitForSelector('[data-testid="revoke-node-btn"]');
    await page.waitForTimeout(500);
    const revokeBtn = page.locator('[data-testid="revoke-node-btn"]').first();
    await revokeBtn.click();
    await page.waitForSelector('[data-testid="destructive-confirm-dialog"]');
    await page.waitForTimeout(500);
    await page.screenshot({ path: path.join(OUTPUT_DIR, '05_fleet_destructive_modal.png') });
    // close modal
    await page.keyboard.press('Escape');
    await page.waitForTimeout(300);

    // 6. Audit Trail Page & Visual Diff Inspector
    console.log('Capturing 06_audit_trail.png...');
    await page.locator('[data-testid="nav-audit"]').click();
    await page.waitForSelector('[data-testid="audit-row"]');
    await page.waitForTimeout(500);
    await page.screenshot({ path: path.join(OUTPUT_DIR, '06_audit_trail.png') });

    // Open diff modal
    const diffBtn = page.locator('[data-testid="audit-inspect-btn"]').first();
    if (await diffBtn.isVisible()) {
      await diffBtn.click();
      await page.waitForSelector('[data-testid="audit-inspect-dialog"]');
      await page.waitForTimeout(500);
      await page.screenshot({ path: path.join(OUTPUT_DIR, '06_audit_diff_modal.png') });
      await page.locator('[data-testid="audit-close-inspect-btn"]').click();
      await page.waitForTimeout(400);
    }

    // 7. Global Keyboard Shortcuts Dialog
    console.log('Capturing 07_keyboard_shortcuts.png...');
    await page.locator('[data-testid="nav-overview"]').click();
    await page.waitForTimeout(500);
    await page.keyboard.press('?');
    await page.waitForSelector('[data-testid="keyboard-help-dialog"]');
    await page.waitForTimeout(400);
    await page.screenshot({ path: path.join(OUTPUT_DIR, '07_keyboard_shortcuts.png') });
    await page.keyboard.press('Escape');
    await page.waitForTimeout(300);

    // 8. Inactivity Idle Timeout Warning Dialog (PCI-DSS v4.0 Req 8.3.6)
    console.log('Capturing 08_idle_timeout_warning.png...');
    await page.evaluate(() => {
      if (typeof window.__showIdleDemo === 'function') {
        window.__showIdleDemo();
      }
    });
    await page.waitForSelector('[data-testid="idle-timeout-modal"]');
    await page.waitForTimeout(400);
    await page.screenshot({ path: path.join(OUTPUT_DIR, '08_idle_timeout_warning.png') });
    await page.evaluate(() => {
      if (typeof window.__hideIdleDemo === 'function') {
        window.__hideIdleDemo();
      }
    });
    await page.waitForTimeout(300);

    // 9. Policies Page
    console.log('Capturing 09_policies.png...');
    await page.locator('[data-testid="nav-policies"]').click();
    await page.waitForTimeout(600);
    await page.screenshot({ path: path.join(OUTPUT_DIR, '09_policies.png') });

    // 10. Users & Service Accounts Page
    console.log('Capturing 10_users_service_accounts.png...');
    await page.locator('[data-testid="nav-users"]').click();
    await page.waitForTimeout(600);
    await page.screenshot({ path: path.join(OUTPUT_DIR, '10_users_service_accounts.png') });

    console.log('ALL SCREENSHOTS CAPTURED SUCCESSFULLY!');
    await browser.close();
    server.close();
    process.exit(0);
  } catch (err) {
    console.error('Failed to capture screenshots:', err);
    server.close();
    process.exit(1);
  }
});
