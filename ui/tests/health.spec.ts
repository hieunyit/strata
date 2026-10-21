import {test,expect} from '@playwright/test';
import {signedIn} from './session';
test('missing health telemetry stays unknown while measured zero is healthy',async({page})=>{
 await signedIn(page,['viewer']);
 await page.route('**/v1/health',r=>r.fulfill({json:{at:new Date().toISOString(),fresh_for_seconds:90,version:'dev',scope:'global',truncated:false,nodes:[],checks:[{id:'postgres',state:'unknown',observed_at:null,advice:'postgres'},{id:'fail_open',state:'healthy',observed_at:new Date().toISOString(),value:'0',advice:'fail_open'}]}}));
 await page.goto('/#/health');
 await expect(page.getByTestId('health-postgres')).toHaveAttribute('data-state','unknown');
 await expect(page.getByTestId('health-fail_open')).toHaveAttribute('data-state','healthy');
 await expect(page.getByTestId('health-fail_open')).toContainText('0');
});
