import { test, expect } from '@playwright/test';
import fs from 'fs';
import path from 'path';

test('audit filters find an older PostgreSQL record outside the latest 200 rows', async ({page,baseURL}) => {
  const password=process.env.STRATA_AUDIT_LAB_PASSWORD,output=process.env.STRATA_AUDIT_EVIDENCE_DIR;
  if(!password||!output||!baseURL)throw new Error('Private audit fixture required');
  const external:string[]=[],errors:string[]=[],urlCredentials:string[]=[];
  page.on('pageerror',e=>errors.push(e.message));
  page.on('request',r=>{const u=new URL(r.url());if(u.searchParams.has('token')||u.searchParams.has('access_token'))urlCredentials.push(u.pathname);});
  await page.route('**/*',async route=>{const u=new URL(route.request().url());if(u.origin!==new URL(baseURL).origin){external.push(u.origin);await route.abort();return;}await route.continue();});
  const login=async(role:string)=>{
    await page.getByTestId('login-username').fill(`example-${role}`);
    await page.getByTestId('login-password').fill(password);
    await page.getByTestId('password-login-btn').click();
    await expect(page.getByTestId('logout-btn')).toBeVisible();
  };
  await page.goto('/#/audit');await login('admin');
  await expect(page.getByTestId('audit-row')).toHaveCount(200);
  await expect(page.getByTestId('audit-result-scope')).toContainText('narrow the filters');
  await expect(page.getByText('example-audit-target',{exact:true})).toHaveCount(0);
  await page.getByTestId('audit-filter-actor').fill('example-audit-target');
  await page.getByTestId('audit-filter-resource').fill('example-old');
  await page.getByTestId('audit-filter-action').fill('Update');
  await page.getByTestId('audit-filter-channel').fill('ui');
  await page.getByTestId('audit-filter-from').fill('2026-10-16T09:59');
  await page.getByTestId('audit-filter-to').fill('2026-10-16T10:01');
  const response=page.waitForResponse(r=>new URL(r.url()).pathname==='/v1/audit'&&new URL(r.url()).searchParams.get('actor')==='example-audit-target');
  await page.getByTestId('audit-apply-filters').click();
  const reply=await response;expect(reply.status()).toBe(200);
  const data=await reply.json();expect(data.has_more).toBe(false);expect(data.entries).toHaveLength(1);
  expect(data.entries[0].subject).toBe('audit-target-subject');
  await expect(page.getByTestId('audit-row')).toHaveCount(1);
  const inspect=page.getByTestId('audit-inspect-btn');await inspect.click();
  const dialog=page.getByRole('dialog');await expect(dialog).toContainText('audit-target-subject');
  await expect(dialog).toContainText('"version": 1');await expect(dialog).toContainText('"version": 2');
  await expect(page.getByTestId('audit-close-inspect-btn')).toBeFocused();
  await page.keyboard.press('Shift+Tab');await expect(dialog.getByRole('button',{name:'Close',exact:true}).last()).toBeFocused();
  await page.keyboard.press('Tab');await expect(page.getByTestId('audit-close-inspect-btn')).toBeFocused();
  await page.keyboard.press('Escape');await expect(dialog).toHaveCount(0);await expect(inspect).toBeFocused();
  const download=page.waitForEvent('download');await page.getByTestId('audit-export-btn').click();
  const csv=await download;const file=await csv.path();if(!file)throw new Error('CSV missing');
  const text=fs.readFileSync(file,'utf8');expect(text).toContain('example-audit-target');expect(text).not.toContain('example-noise');
  await page.getByTestId('language-toggle-btn').click();await page.setViewportSize({width:390,height:844});
  await expect(page.getByTestId('audit-apply-filters')).toHaveText('Áp dụng bộ lọc');
  await page.screenshot({path:path.join(output,'audit-mobile-vi.png'),fullPage:true});
  const bounds=await page.getByTestId('audit-server-filters').boundingBox();
  expect(!!bounds&&bounds.x>=0&&bounds.x+bounds.width<=390).toBe(true);
  const denied:Record<string,number>={};
  for(const role of ['viewer','approver']){
    await page.getByTestId('logout-btn').click();await login(role);
    denied[role]=await page.evaluate(async()=>{
      const session=JSON.parse(sessionStorage.getItem('strata.localSession')??'{}');
      return(await fetch('/v1/audit?actor=example-audit-target',{headers:{Authorization:`Bearer ${session.token}`}})).status;
    });
    expect(denied[role]).toBe(403);
    await expect(page.getByTestId('audit-panel')).toHaveCount(0);
  }
  expect(errors).toEqual([]);expect(external).toEqual([]);expect(urlCredentials).toEqual([]);
  fs.writeFileSync(path.join(output,'browser-result.json'),JSON.stringify({older_match_found:true,initial_rows:200,filtered_rows:1,subject_preserved:true,export_matches_filter:true,denied,mobile_bounds:bounds,errors,external,urlCredentials,scope:'real local auth/API/PostgreSQL; no production/GeoIP/rollout'},null,2)+'\n');
});
