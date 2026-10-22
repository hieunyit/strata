import { test, expect } from '@playwright/test';
import { signedIn } from './session';

// RS-4: an operator turns a bot set to block, overrides one rule of an
// attack set with a reason, sees what the draft changes, and saves.

const policy = {
  id: 'example-api', name: 'example-api', version: 2, etag: 'etag-2',
  spec: { mode: 'MODE_SHADOW', rule_sets: [{ set: 'bots-scanners', action: 'POLICY_RULE_ACTION_LOG' }, { set: 'bots-trusted', action: 'POLICY_RULE_ACTION_LOG' }] },
  created_by: 'lab-operator', update_time: '2026-10-22T10:00:00Z',
};

const sets = [
  { name: 'attack-sqli', group: 'attack', title: { vi: 'SQL injection', en: 'SQL injection' }, match: { sources: ['crs', 'strata'], attack_types: ['sql-injection'] }, rule_count: 58 },
  { name: 'attack-xss', group: 'attack', title: { vi: 'Cross-site scripting (XSS)', en: 'Cross-site scripting (XSS)' }, match: { sources: ['crs', 'strata'], attack_types: ['xss'] }, rule_count: 31 },
  { name: 'virtual-patches', group: 'signature', title: { vi: 'Bản vá ảo cho CVE', en: 'CVE virtual patches' }, match: { sources: ['strata-virtual-patch'] }, rule_count: 10 },
  { name: 'technology-wordpress', group: 'technology', title: { vi: 'WordPress', en: 'WordPress' }, match: { tags: ['wordpress'] }, rule_count: 37 },
  { name: 'bots-scanners', group: 'bot', class: 'malicious', title: { vi: 'Công cụ quét lỗ hổng', en: 'Vulnerability scanners' }, match: { tags: ['scanner'] }, rule_count: 48 },
  { name: 'bots-ai-crawlers', group: 'bot', class: 'untrusted', title: { vi: 'Crawler AI', en: 'AI crawlers' }, match: { tags: ['ai-crawler'] }, rule_count: 64 },
  { name: 'bots-trusted', group: 'bot', class: 'trusted', title: { vi: 'Bot tin cậy', en: 'Trusted bots' }, match: { tags: ['search-engine'] }, rule_count: 118 },
];

test('rule sets and overrides in the policy editor', async ({ page }) => {
  await signedIn(page, ['operator'], 'lab-operator');
  let patched: { spec?: unknown } | undefined;
  const versions = [{ policy_id: 'example-api', version: 2, spec: policy.spec, state: 'DEPLOYED', create_time: '2026-10-22T10:00:00Z', created_by: 'lab-operator' }];
  await page.route('**/v1/policies', (r) => r.fulfill({ json: { policies: [policy] } }));
  await page.route('**/v1/policies/example-api/versions', (r) => r.fulfill({ json: { versions } }));
  await page.route('**/v1/policies/example-api', async (r) => {
    if (r.request().method() !== 'PATCH') return r.fallback();
    patched = r.request().postDataJSON();
    await r.fulfill({ json: { policy: { ...policy, version: 3, etag: 'etag-3' } } });
  });
  await page.route((url) => url.pathname === '/v1/rule-sets', (r) => r.fulfill({ json: { sets, catalog_available: true } }));
  await page.route('**/v1/rule-sets/attack-sqli/rules*', (r) => r.fulfill({ json: {
    set: 'attack-sqli', total: 2, next_cursor: 0,
    rules: [
      { id: 942100, name: 'SQL Injection Attack Detected via libinjection', pack: 'core', digest: 'a', severity: 'critical', paranoia_level: 1 },
      { id: 942190, name: 'Detects MSSQL code execution and information gathering attempts', pack: 'core', digest: 'b', severity: 'critical', paranoia_level: 1 },
    ],
  } }));
  await page.route('**/v1/rule-sets:resolve*', async (r) => {
    const draft = r.request().postDataJSON();
    const blocking = (draft.rule_sets ?? []).some((s: { set: string; action: string }) => s.set === 'bots-scanners' && s.action === 'block');
    await r.fulfill({ json: {
      total: blocking ? 1 : 0, next_cursor: 0,
      counts: { block: blocking ? 48 : 0, log: blocking ? 9183 : 9231, off: 0, score: 512 },
      rules: blocking ? [{ id: 500300, name: 'Example scanner user agent', pack: 'signature', digest: 'c', action: 'block', own: 'log', source: 'set', set: 'bots-scanners' }] : [],
    } });
  });
  await page.goto('/#/policies');
  await page.getByTestId('policy-row').click();
  await page.getByTestId('policy-edit').click();

  await expect(page.getByTestId('ruleset-on-bots-scanners')).toBeChecked();
  await page.getByTestId('ruleset-action-bots-scanners').selectOption('POLICY_RULE_ACTION_BLOCK');
  await expect(page.getByTestId('rulesets-impact')).toContainText('48 rules block alone');
  await page.getByTestId('rulesets-changed').click();
  await expect(page.getByTestId('rulesets-changed-list')).toContainText('log → block');

  await page.getByTestId('ruleset-view-attack-sqli').click();
  await page.getByTestId('ruleset-rule-action-942190').selectOption('POLICY_RULE_ACTION_OFF');
  await expect(page.getByTestId('editor-save')).toBeDisabled();
  await page.getByTestId('ruleset-rule-reason-942190').fill('FP on the admin search');
  await page.screenshot({ path: '../docs/reports/rs/rs4-rule-sets.png', fullPage: true });

  await page.setViewportSize({ width: 390, height: 844 });
  await page.getByTestId('editor-rule-sets').scrollIntoViewIfNeeded();
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  expect(overflow).toBeLessThanOrEqual(0);
  await page.screenshot({ path: '../docs/reports/rs/rs4-rule-sets-phone.png', fullPage: true });

  await page.getByTestId('editor-save').click();
  await expect(page.getByTestId('editor-saved')).toBeVisible();
  expect(patched?.spec).toEqual({
    mode: 'MODE_SHADOW',
    rule_sets: [{ set: 'bots-scanners', action: 'POLICY_RULE_ACTION_BLOCK' }, { set: 'bots-trusted', action: 'POLICY_RULE_ACTION_LOG' }],
    rule_overrides: [{ rule: 942190, action: 'POLICY_RULE_ACTION_OFF', reason: 'FP on the admin search' }],
  });
});

// RS-4b: the catalog filtered by a set chosen from a list, the sets of
// each rule, and an override for a chosen policy.
test('rules page: filter by set, override for a policy', async ({ page }) => {
  await signedIn(page, ['operator'], 'lab-operator');
  const digest = 'a'.repeat(64);
  const rows = [
    { id: 913100, name: 'Found User-Agent associated with security scanner', pack: 'core', digest, source: 'crs', version: '4.25.2', attack_type: 'scanner', sets: ['attack-scanner-probes'] },
    { id: 942100, name: 'SQL Injection Attack Detected via libinjection', pack: 'core', digest, source: 'crs', version: '4.25.2', attack_type: 'sql-injection', sets: ['attack-sqli'] },
    { id: 942190, name: 'Detects MSSQL code execution and information gathering attempts', pack: 'core', digest, source: 'crs', version: '4.25.2', attack_type: 'sql-injection', sets: ['attack-sqli'] },
    { id: 700005, name: 'Virtual patch for an example CVE', pack: 'core', digest, source: 'strata-virtual-patch', version: '1', attack_type: 'rce', cves: ['CVE-2026-12345'], sets: ['virtual-patches', 'signatures-kev'] },
  ];
  let lastSet = '';
  let patched: { spec?: unknown } | undefined;
  await page.route((url) => url.pathname === '/v1/rule-sets', (r) => r.fulfill({ json: { sets: [...sets, { name: 'signatures-kev', group: 'signature', title: { vi: 'CVE đang bị khai thác (CISA KEV)', en: 'Known exploited CVEs (CISA KEV)' }, match: { tags: ['kev'] }, rule_count: 212 }, { name: 'attack-scanner-probes', group: 'attack', title: { vi: 'Dò quét', en: 'Scanner probes' }, match: { attack_types: ['scanner'] }, rule_count: 12 },
    { name: 'custom-internal-scanners', group: 'custom', custom: true, title: { vi: 'Internal scanners', en: 'Internal scanners' }, description: 'Scanners of our security team', match: { tags: ['scanner'], ids: [913100, 913101, 913102] }, rule_count: 51, version: 3, etag: 'e3', updated_by: 'lab-operator' }], catalog_available: true } }));
  await page.route((url) => url.pathname === '/v1/rule-catalog', (r) => {
    lastSet = new URL(r.request().url()).searchParams.get('set') ?? '';
    const shown = lastSet ? rows.filter((x) => x.sets.includes(lastSet)) : rows;
    return r.fulfill({ json: { rules: shown, next_cursor: 0, digest, at: '2026-10-23T00:00:00Z', stale: false, source: 'configured_catalog', total: 9420, matched: lastSet ? shown.length : 9420,
      facets: { sources: ['crawler-user-agents', 'crs', 'et-open', 'sigma', 'strata', 'strata-virtual-patch'], attack_types: ['bot', 'rce', 'scanner', 'sql-injection', 'xss'] } } });
  });
  await page.route((url) => url.pathname === '/v1/rule-catalogs', (r) => r.fulfill({ json: { catalogs: [] } }));
  await page.route((url) => url.pathname === '/v1/applications', (r) => r.fulfill({ json: { applications: [], next_cursor: '' } }));
  await page.route((url) => url.pathname === '/v1/policies', (r) => r.fulfill({ json: { policies: [policy] } }));
  await page.route((url) => url.pathname === '/v1/policies/example-api', async (r) => {
    if (r.request().method() !== 'PATCH') return r.fallback();
    patched = r.request().postDataJSON();
    await r.fulfill({ json: { policy: { ...policy, version: 3, etag: 'etag-3' } } });
  });
  await page.goto('/#/rules');
  await expect(page.getByTestId('rules-matched')).toContainText('9420 of 9420');
  await expect(page.getByTestId('custom-row')).toContainText('tags=scanner ids=913100,913101,913102');
  await page.getByTestId('rules-set').selectOption('attack-sqli');
  await expect(page.getByTestId('rules-matched')).toContainText('2 of 9420');
  expect(lastSet).toBe('attack-sqli');
  await page.getByTestId('rules-override-942190').click();
  await page.getByTestId('override-policy').selectOption('example-api');
  await expect(page.getByText('Policy example-api · version 2')).toBeVisible();
  await page.getByTestId('override-action').selectOption('POLICY_RULE_ACTION_OFF');
  await page.getByTestId('override-reason').fill('FP on the admin search');
  await page.screenshot({ path: '../docs/reports/rs/rs4b-rules.png', fullPage: true });
  await page.getByTestId('override-save').click();
  await expect(page.getByTestId('override-created')).toBeVisible();
  expect(patched?.spec).toEqual({ ...policy.spec, rule_overrides: [{ rule: 942190, action: 'POLICY_RULE_ACTION_OFF', reason: 'FP on the admin search' }] });

  await page.setViewportSize({ width: 390, height: 844 });
  await page.getByTestId('rules-set').selectOption('');
  await expect(page.getByTestId('rules-matched')).toContainText('9420 of 9420');
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  expect(overflow).toBeLessThanOrEqual(0);
  await page.screenshot({ path: '../docs/reports/rs/rs4b-rules-phone.png', fullPage: true });
});
