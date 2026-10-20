import {test,expect} from '@playwright/test';
import {signedIn} from './session';
test('application dashboard scopes statistics and marks missing request coverage',async({page})=>{
 await signedIn(page,['viewer']);
 const application={id:'example-api',name:'Example API',owner:'Team',etag:'e',environments:[{id:'prod',name:'Production',group_id:'edge'}],routes:[{id:'api',environment_id:'prod',host:'api.example.test',path_prefix:'/',policy_id:'p1',schema_id:''}],created_at:new Date().toISOString(),updated_at:new Date().toISOString()};
 await page.route('**/v1/applications?*',r=>r.fulfill({json:{applications:[application],next_cursor:''}}));
 await page.route('**/v1/policies',r=>r.fulfill({json:{policies:[]}}));
 await page.route('**/v1/applications/example-api/overview?*',r=>r.fulfill({json:{totals:{events:8,block:3,shadow:5,error:0},telemetry_scope:'events_only'}}));
 await page.goto('/#/applications');
 await page.getByText('Example API · Team').click();
 await expect(page.getByTestId('application-stats')).toContainText('8');
 await expect(page.getByText(/Protection coverage unknown/)).toBeVisible();
 await expect(page.getByText('api.example.test')).toBeVisible();
 await expect(page.getByTestId('application-editor')).toHaveCount(0);
});
