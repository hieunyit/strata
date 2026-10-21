import { expect, test } from '@playwright/test';
import { signedIn } from './session';
const digest='a'.repeat(64), previous='b'.repeat(64);
const catalog={rules:[{id:700011,name:'Example virtual patch',pack:'core',digest,source:'strata',version:'1.2',cves:['CVE-2026-12345'],owner:'example-team'}],next_cursor:0,digest,at:'2026-10-21T00:00:00Z',stale:false,source:'configured_catalog',total:1};
const exceptions={exceptions:[{policy_id:'policy-api',policy_name:'example-api',policy_version:2,etag:'policy-etag',exception:{id:'exc-0123456789abcdef0123456789abcdef',rule_id:700011,method:'POST',host:'api.example.test',path:'/api/search',field:'ARGS:q',expires_unix_ms:1792540800000,reason:'example'},origin:{owner:'oidc:operator',created_at:'2026-10-20T00:00:00Z'},state:'DRAFT',decided_by:'',approved_replay_id:'',warnings:['expired'],match_source:'not_collected',unused_status:'unknown',editable:true,active_nodes:0}],maintenance:[],next_cursor:'',at:'2026-10-21T00:00:00Z'};

test('catalog content diff and unknown measured cost',async({page})=>{
 await signedIn(page,['viewer']);
 await page.route('**/v1/**',async route=>{
  const path=new URL(route.request().url()).pathname;
  if(path.startsWith('/v1/auth/')||path==='/v1/version'){await route.fallback();return;}
  if(path==='/v1/applications'){await route.fulfill({json:{applications:[{id:'example-api',name:'Example',environments:[{id:'test',name:'Test'}],routes:[]}],next_cursor:''}});return;}
  if(path==='/v1/rule-catalog'){await route.fulfill({json:catalog});return;}
  if(path==='/v1/rule-catalogs'){await route.fulfill({json:{catalogs:[{digest:previous,created_at:'2026-10-20T00:00:00Z',last_seen_at:'2026-10-20T00:00:00Z',current:false,rules:1}]}});return;}
  if(path==='/v1/rule-catalogs:diff'){await route.fulfill({json:{added:0,removed:0,modified:1,changes:[{id:700011,kind:'modified',before:{name:'Old',pack:'core',digest:previous,version:'1.1'},after:catalog.rules[0]}],next_cursor:0}});return;}
  if(path==='/v1/rule-catalog/700011'){await route.fulfill({json:{rule:catalog.rules[0],usage:[],health:null,health_status:'unavailable'}});return;}
  await route.fulfill({status:503,json:{error:'unmocked'}});
 });
 await page.goto('/#/rules');
 await page.getByRole('combobox',{name:'Application',exact:true}).selectOption('example-api');await page.getByRole('combobox',{name:'Environment',exact:true}).selectOption('test');
 await page.getByRole('button',{name:'700011 · Example virtual patch'}).click();await expect(page.getByText('Sampled mean rule cost: Unknown')).toBeVisible();
 await page.getByRole('combobox',{name:'Baseline snapshot',exact:true}).selectOption(previous);await page.getByRole('button',{name:'Compare',exact:true}).click();await expect(page.getByText('Added 0, removed 0, modified 1.')).toBeVisible();
 await page.screenshot({path:'../docs/reports/cp-c02-rules.png',fullPage:true});
});
test('exception revocation creates a draft without activation',async({page})=>{
 await signedIn(page,['operator']);
 await page.route('**/v1/**',async route=>{
  const path=new URL(route.request().url()).pathname;
  if(path.startsWith('/v1/auth/')||path==='/v1/version'){await route.fallback();return;}
  if(path==='/v1/applications'){await route.fulfill({json:{applications:[{id:'example-api',name:'Example',environments:[{id:'test',name:'Test'}],routes:[]}],next_cursor:''}});return;}
  if(path==='/v1/exceptions'){await route.fulfill({json:exceptions});return;}
  if(path==='/v1/exceptions:revoke'){const body=route.request().postDataJSON();expect(body.etag).toBe('policy-etag');expect(body.request_id).toBeTruthy();await route.fulfill({json:{policy_id:'policy-api',policy_version:3,etag:'new',state:'DRAFT',replay_url:'/v1/policies/policy-api/versions/3/replay'}});return;}
  await route.fulfill({status:503,json:{error:'unmocked'}});
 });
 await page.goto('/#/exceptions');await page.getByRole('combobox',{name:'Application',exact:true}).selectOption('example-api');await page.getByRole('combobox',{name:'Environment',exact:true}).selectOption('test');
 await expect(page.getByText('Expired at runtime')).toBeVisible();await page.getByRole('button',{name:'Create revocation draft'}).click();await expect(page.getByText('Draft version 3 created.')).toBeVisible();
 await page.screenshot({path:'../docs/reports/cp-c02-exceptions.png',fullPage:true});
});
