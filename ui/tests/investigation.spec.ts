import { expect, test } from '@playwright/test';
import { signedIn } from './session';

const block = 'STR-0000-0000-0000-0001';
const event = {block_id:block,timestamp:'2026-10-21T00:00:00Z',node_id:'node-a',connector_type:'nginx',policy_id:'example-api',policy_version:1,client_ip:'198.51.100.0/24',http_method:'GET',http_host:'api.example.test',http_path:'/api/search',status_code:403,action:'block',geoip_version:'synthetic-test',country_iso:'VN'};
test('saved search uses an opaque link and evidence runs asynchronously', async ({page})=>{
 await signedIn(page,['operator']);
 let saved: Record<string,unknown> = {}, exported = false;
 await page.route('**/v1/**',async route=>{
  const request=route.request(),url=new URL(request.url()),path=url.pathname;
  if(path.startsWith('/v1/auth/')||path==='/v1/version'){await route.fallback();return;}
  if(path==='/v1/applications'){await route.fulfill({json:{applications:[{id:'example-api',name:'Example',environments:[{id:'test',name:'Test'}],routes:[]}],next_cursor:''}});return;}
  if(path==='/v1/events:search'){await route.fulfill({json:{events:[],total_matched:0}});return;}
  if(path==='/v1/saved-searches'&&request.method()==='POST'){
   const body=request.postDataJSON();expect(body.request_id).toBeTruthy();expect(body.search.environment_id).toBe('test');
   saved={...body.search,id:'opaque-search',owner:'oidc:lab-operator',editable:true,etag:'etag',expires_at:'2027-01-01T00:00:00Z'};
   await route.fulfill({json:{search:saved}});return;
  }
  if(path==='/v1/saved-searches'){await route.fulfill({json:{searches:[],next_cursor:''}});return;}
  if(path==='/v1/saved-searches/opaque-search'){if(request.method()==='PUT'){const body=request.postDataJSON();expect(body.search.shared).toBe(false);saved={...saved,...body.search,etag:'etag-next'};}await route.fulfill({json:{search:saved}});return;}
  if(path==='/v1/saved-searches/opaque-search:search'){await route.fulfill({json:{events:[event],total_matched:1}});return;}
  const job={id:'opaque-export',owner:'oidc:lab-operator',application_id:'example-api',environment_id:'test',sensitive:false,state:'pending',row_count:0,truncated:false,etag:'job-etag',sha256:'test',created_at:'2026-10-21T00:00:00Z',expires_at:'2026-10-22T00:00:00Z'};
  if(path==='/v1/evidence'&&request.method()==='POST'){exported=true;await route.fulfill({status:202,json:{export:job}});return;}
  if(path==='/v1/evidence'){await route.fulfill({json:{exports:[]}});return;}
  if(path==='/v1/evidence/opaque-export'){await route.fulfill({json:{export:{...job,state:'done',row_count:1}}});return;}
  if(path==='/v1/evidence/opaque-export/download'){
   expect(request.headers().authorization).toMatch(/^Bearer /);
   await route.fulfill({contentType:'text/csv',headers:{'Content-Disposition':'attachment; filename="evidence.csv"'},body:'block_id,client_ip\r\n'+block+',198.51.100.0/24\r\n'});return;
  }
  await route.fulfill({status:503,json:{error:'unmocked '+path}});
 });
 await page.goto('/#/events');
 await page.getByRole('combobox',{name:'Application',exact:true}).selectOption('example-api');
 await page.getByRole('combobox',{name:'Environment',exact:true}).selectOption('test');
 await page.getByLabel('Search title').fill('Case A');await page.getByLabel('Share with authorized users').check();
 await page.getByRole('button',{name:'Save current filter'}).click();
 await expect(page).toHaveURL(/#\/events\?saved=opaque-search$/);await expect(page.getByTestId('event-row')).toHaveCount(1);
 await page.getByRole('button',{name:'Export evidence',exact:true}).click();await expect(page.getByText('Export ready',{exact:false})).toBeVisible();expect(exported).toBe(true);
 const downloading=page.waitForEvent('download');await page.getByRole('button',{name:'Download evidence'}).click();expect((await downloading).suggestedFilename()).toMatch(/^evidence-/);
 await page.getByLabel('Share with authorized users').uncheck();await page.getByRole('button',{name:'Update saved search'}).click();await expect(page.getByLabel('Share with authorized users')).not.toBeChecked();
});

test('investigation saves a case then creates a log-only policy draft',async({page})=>{
 await signedIn(page,['operator']);
 let current={block_id:block,assignee:'',status:'open',note:'',etag:'case-etag',expires_at:'2026-11-21T00:00:00Z'};
 await page.route('**/v1/**',async route=>{
  const r=route.request(),path=new URL(r.url()).pathname;
  if(path.startsWith('/v1/auth/')||path==='/v1/version'){await route.fallback();return;}
  if(path==='/v1/events/'+block){await route.fulfill({json:{event,rules:{}}});return;}
  if(path==='/v1/events/'+block+':case'){
   if(r.method()==='POST'){const body=r.postDataJSON();expect(body.case.etag).toBe('case-etag');expect(body.request_id).toBeTruthy();current={...body.case,etag:'case-next'};}
   await route.fulfill({json:{case:current}});return;
  }
  if(path==='/v1/policies'){await route.fulfill({json:{policies:[{id:'policy-api',name:'example-api',etag:'policy-etag',version:1}]}});return;}
  if(path==='/v1/events/'+block+':propose-rule'){
   const body=r.postDataJSON();expect(body.action).toBe('log');expect(body.etag).toBe('policy-etag');
   await route.fulfill({json:{policy_id:'policy-api',policy_version:2,etag:'next',state:'DRAFT',replay_url:'/v1/policies/policy-api/versions/2/replay'}});return;
  }
  await route.fulfill({status:503,json:{error:'unmocked '+path}});
 });
 await page.goto('/#/events/'+block);await page.getByRole('combobox',{name:'Status',exact:true}).selectOption('investigating');await page.getByRole('button',{name:'Assign to me'}).click();await page.getByLabel('Investigation note').fill('Review synthetic event');await page.getByRole('button',{name:'Save case'}).click();
 await expect(page.getByRole('combobox',{name:'Status',exact:true})).toBeEnabled();await page.getByRole('button',{name:'Propose geo rule'}).click();await expect(page.getByText('Draft version 2 created.',{exact:false})).toBeVisible();
});
