import {expect,test} from '@playwright/test';
import {signedIn} from './session';
const digest='a'.repeat(64),key='b'.repeat(64);
const operation={path:'/api/users/{param1}',method:'POST',content_types:['application/json'],max_body_bytes:65536};
const endpoint={key,route_id:'api',path:operation.path,method:'POST',content_types:['application/json'],samples:20,independent_sources:3,first_seen:'2026-10-21T00:00:00Z',last_seen:'2026-10-21T00:20:00Z',observed_max_body_bytes:234,eligible:true};
const proposal={id:'proposal-a',application_id:'example-api',environment_id:'test',route_id:'api',base_digest:digest,operations:[operation],digest:key,evidence:endpoint,changes:[{path:operation.path,method:'POST',kind:'added',before:null,after:operation}],etag:'proposal-etag',owner:'oidc:operator',created_at:'2026-10-21T00:00:00Z',expires_at:'2026-11-21T00:00:00Z',draft_policy_id:'',draft_version:0,review_state:'PROPOSED',policy_id:'policy-api',policy_etag:'policy-etag',policy_version:1,draftable:true};
const inventory={endpoints:[endpoint],document:{application_id:'example-api',environment_id:'test',etag:'doc-etag',operations:[],digest,updated_at:'2026-10-21T00:00:00Z',owner:'oidc:operator'},document_etag:'doc-etag',scope_changed:false,proposals:[],editable:true,collection_enabled:false,approval_expires_at:null,runtime_enforcement:false,source:'trusted_backend_2xx_only',limits:{min_samples:20,min_sources:3,min_span_seconds:600,retention_days:7}};
test('discovery stays legally disabled and proposals become reviewed drafts only',async({page})=>{
 await signedIn(page,['operator']);let proposed=false;let submitted=false;let draftCreated=false;
 await page.route('**/v1/**',async route=>{
  const req=route.request(),path=new URL(req.url()).pathname;
  if(path.startsWith('/v1/auth/')||path==='/v1/version'){await route.fallback();return;}
  if(path==='/v1/applications'){await route.fulfill({json:{applications:[{id:'example-api',name:'Example',environments:[{id:'test',name:'Test'}],routes:[]}],next_cursor:''}});return;}
  if(path==='/v1/discovery'){await route.fulfill({json:{...inventory,proposals:proposed?[{...proposal,draft_policy_id:draftCreated?'policy-api':'',draft_version:draftCreated?2:0,review_state:submitted?'SUBMITTED':draftCreated?'DRAFT':'PROPOSED',draftable:!draftCreated}]:[]}});return;}
  if(path==='/v1/discovery/proposals'){const body=req.postDataJSON();expect(body.endpoint_key).toBe(key);expect(body.request_id).toBeTruthy();proposed=true;await route.fulfill({json:proposal});return;}
  if(path==='/v1/discovery/proposals:draft'){const body=req.postDataJSON();expect(body.etag).toBe('proposal-etag');expect(body.policy_etag).toBe('policy-etag');draftCreated=true;await route.fulfill({json:{policy_id:'policy-api',policy_version:2,etag:'next',state:'DRAFT',replay_url:'/v1/policies/policy-api/versions/2/replay'}});return;}
  if(path==='/v1/policies/policy-api/versions'){await route.fulfill({json:{versions:[{policy_id:'policy-api',version:2,state:submitted?'SUBMITTED':'DRAFT',spec:{mode:'MODE_SHADOW'},created_by:'writer',submitted_by:submitted?'writer':''}]}});return;}
  if(path==='/v1/policies/policy-api/versions/2/replay'){await route.fulfill({json:{operation:{id:'replay-a',policy_id:'policy-api',version:2,kind:'REPLAY',state:'PENDING',done:false}}});return;}
  if(path==='/v1/policies/policy-api:submit'){const body=req.postDataJSON();expect(body.version).toBe(2);submitted=true;await route.fulfill({json:{version:{policy_id:'policy-api',version:2,state:'SUBMITTED'}}});return;}
  if(path==='/v1/discovery/proposals/proposal-a'){expect(req.headers().authorization).toMatch(/^Bearer /);await route.fulfill({contentType:'application/json',headers:{'Content-Disposition':'attachment; filename="openapi-proposal.json"'},body:JSON.stringify({openapi:'3.0.3','x-strata-mode':'documentation_only',paths:{}})});return;}
  await route.fulfill({status:503,json:{error:'unmocked'}});
 });
 await page.goto('/#/discovery');await page.getByRole('combobox',{name:'Application',exact:true}).selectOption('example-api');await page.getByRole('combobox',{name:'Environment',exact:true}).selectOption('test');
 await expect(page.getByText('Collection is disabled or approval has expired.')).toBeVisible();await expect(page.getByRole('note')).toContainText('This runtime does not enforce OpenAPI.');
 await page.getByRole('button',{name:'Propose changes',exact:true}).click();await page.getByRole('button',{name:'Create draft and replay',exact:true}).click();await expect(page.getByText('Draft version 2 created.')).toBeVisible();
 await page.getByRole('button',{name:'Review draft and replay',exact:true}).click();await expect(page.getByTestId('version-review')).toContainText('policy-api · v2');
 const file=page.waitForEvent('download');await page.getByRole('button',{name:'Download OpenAPI proposal'}).click();expect((await file).suggestedFilename()).toBe('openapi-proposal.json');
 await page.evaluate(()=>window.scrollTo(0,0));
 await page.screenshot({path:'../docs/reports/cp-c05-discovery.png',fullPage:true});
});
