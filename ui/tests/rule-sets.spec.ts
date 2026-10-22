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
  await page.route('**/v1/rule-sets', (r) => r.fulfill({ json: { sets, catalog_available: true } }));
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
