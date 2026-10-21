import {expect,test} from '@playwright/test';
import {signedIn} from './session';
test('acknowledges a grouped incident and enables a daily report',async({page})=>{
 await signedIn(page,['operator']);let acknowledged=false,enabled=false;
 await page.route('**/v1/**',async route=>{
  const req=route.request(),path=new URL(req.url()).pathname;
  if(path.startsWith('/v1/auth/')||path==='/v1/version'){await route.fallback();return;}
  if(path==='/v1/applications'){await route.fulfill({json:{applications:[{id:'example-api',name:'Example',environments:[{id:'test',name:'Test'}],routes:[]}],next_cursor:''}});return;}
  if(path==='/v1/incidents'){await route.fulfill({json:{editable:true,limit:200,incidents:[{id:'incident-a',application_id:'example-api',environment_id:'test',kind:'heartbeat',state:acknowledged?'acknowledged':'open',signal_state:'degraded',affected:3,etag:'incident-etag',opened_at:'2026-10-21T00:00:00Z',observed_at:'2026-10-21T00:00:00Z',notified_at:null,ack_subject:''}]}});return;}
  if(path==='/v1/incidents:acknowledge'){const body=req.postDataJSON();expect(body.etag).toBe('incident-etag');expect(body.request_id).toBeTruthy();acknowledged=true;await route.fulfill({json:{}});return;}
  if(path==='/v1/report-schedule'){if(req.method()==='PUT'){const body=req.postDataJSON();expect(body.request_id).toBeTruthy();expect(body.schedule.every_hours).toBe(24);enabled=body.schedule.enabled;}await route.fulfill({json:{editable:true,scope_changed:false,schedule:enabled?{application_id:'example-api',environment_id:'test',enabled:true,every_hours:24,etag:'schedule-etag',owner:'oidc:operator',next_run:'2026-10-22T00:00:00Z'}:null}});return;}
  if(path==='/v1/application-reports'){await route.fulfill({json:{reports:[]}});return;}
  await route.fulfill({status:503,json:{error:'unmocked'}});
 });
 await page.goto('/#/operations');await page.getByRole('combobox',{name:'Application',exact:true}).selectOption('example-api');await page.getByRole('combobox',{name:'Environment',exact:true}).selectOption('test');
 await page.getByRole('button',{name:'Acknowledge',exact:true}).click();await expect(page.getByText('Acknowledged · Attention needed')).toBeVisible();
 await page.getByRole('checkbox',{name:'Enable scheduled reports'}).check();await page.getByRole('button',{name:'Save',exact:true}).click();await expect(page.getByText('Schedule saved.')).toBeVisible();expect(enabled).toBe(true);
 await page.screenshot({path:'../docs/reports/cp-c04-operations.png',fullPage:true});
});
