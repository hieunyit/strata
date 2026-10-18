import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { chromium } from '../../ui/node_modules/playwright/index.mjs';

const options = Object.fromEntries(process.argv.slice(2).reduce((all, value, i, raw) => i % 2 ? all : [...all, [value, raw[i + 1]]], []));
const proxy = options['--proxy'];
const out = options['--out'];
assert.match(proxy, /^http:\/\/127\.0\.0\.1:\d+$/);
assert.ok(out);
const source = JSON.parse(fs.readFileSync('docs/reports/h7-header-coverage/gotestwaf.json', 'utf8'));
const payload = source.bypassed[0].payload;
assert.equal(new Set(source.bypassed.map((x) => x.payload)).size, 1);
const browser = await chromium.launch();
const context = await browser.newContext();
const rows = [];
const failures = [];
let completed = false;
const save = () => fs.writeFileSync(path.join(out, 'browser-results.json'), JSON.stringify({
  browser_version: browser.version(), completed, failures, browser_pairs: rows.length,
  browser_http_attempts: rows.reduce((count, row) => count + Number(Boolean(row.baseline)) + Number(Boolean(row.proxy)), 0),
  discovery_http_attempts: 1, rows,
  scope: 'synthetic attribute reflection; tag stripping and output encoding are explicit; actual app context unknown',
}, null, 2) + '\n');
try {
  const discovery = await context.request.get(proxy + '/reflect', { headers: { 'X-Example-Text': 'ordinary header' } });
  assert.equal(discovery.status(), 200);
  const baseline = discovery.headers()['x-example-origin'];
  assert.match(baseline, /^http:\/\/127\.0\.0\.1:\d+$/);
  assert.notEqual(baseline, proxy);
  const allowed = new Set([baseline, proxy]);
  await context.route('**/*', async (route) => {
    if (!allowed.has(new URL(route.request().url()).origin)) {
      failures.push('unexpected external request');
      await route.abort();
      return;
    }
    await route.continue();
  });
  const tests = [{ id: 'benign', encoder: 'URL', pipeline: 'raw', payload: 'ordinary header', executes: false },
    { id: 'positive-control', encoder: 'URL', pipeline: 'raw', payload: '" autofocus onfocus=alert(1)//', executes: true }];
  for (const encoder of ['URL', 'Base64Flat']) for (const pipeline of ['raw', 'strip', 'escaped']) {
    tests.push({ id: `${encoder}-${pipeline}`, encoder, pipeline, payload, executes: pipeline === 'strip' });
  }
  for (const test of tests) {
    const encoded = test.encoder === 'URL' ? encodeURIComponent(test.payload) : Buffer.from(test.payload).toString('base64');
    const row = { id: test.id, encoder: test.encoder, pipeline: test.pipeline, encoded_header: encoded, expected_direct_execution: test.executes };
    rows.push(row);
    for (const [kind, origin] of [['baseline', baseline], ['proxy', proxy]]) {
      const page = await context.newPage();
      await page.setExtraHTTPHeaders({ 'X-Example-Text': encoded });
      const response = await page.goto(`${origin}/reflect?e=${test.encoder === 'URL' ? 0 : 1}&c=${['raw', 'strip', 'escaped'].indexOf(test.pipeline)}`);
      assert.ok(response);
      const status = response.status();
      let alerts = [], attributes = {}, focused = false;
      if (status === 200) {
        await page.locator('#probe').focus();
        await page.waitForTimeout(50);
        ({ alerts, attributes, focused } = await page.evaluate(() => {
          const input = document.querySelector('#probe');
          return { alerts: window.__h7alerts, attributes: Object.fromEntries([...input.attributes].map((a) => [a.name, a.value])), focused: document.activeElement === input };
        }));
        assert.ok(focused, 'real browser must focus the reflected input');
      }
      row[kind] = { status, action: response.headers()['x-probe-action'] ?? null, rules: response.headers()['x-probe-rules'] ?? null, alerts, attributes, focused };
      try {
        if (kind === 'baseline') { assert.equal(status, 200); assert.equal(alerts.includes('1'), test.executes, test.id); }
        else if (test.id === 'positive-control') { assert.equal(status, 403); assert.equal(row.proxy.action, 'block'); }
        else { assert.equal(status, 200); assert.equal(row.proxy.action, 'allow'); assert.equal(alerts.includes('1'), test.executes, test.id); }
      } catch (error) { failures.push(`${test.id}/${kind}: ${error.message}`); }
      await page.close();
    }
  }
  completed = true;
  assert.deepEqual(failures, [], 'browser/WAF failures; see browser-results.json');
  console.log(`PASS ${rows.length} paired browser contexts / ${rows.length * 2} navigations + discovery; positive control blocked; conditional execution observed`);
} finally { save(); await context.close(); await browser.close(); }
