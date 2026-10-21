import {test,expect} from '@playwright/test';
import {signedIn} from './session';
test('stale replay baseline requires explicit acknowledgement',async({page})=>{
 await signedIn(page,['operator']);
 const release={id:'release-a',etag:'e1',state:'APPROVED',snapshot_hash:'abc',created_by:'operator',approved_by:'reviewer',source_release:'',snapshot:{bundle:{contents:{'example-api':2},input_digest:'inputs',rules_digest:'rules'},baseline_bundle:'41',replay_ids:{},canary:{block_factor:3},waves:[0,1],soak_seconds:30}};
 await page.route('**/v1/releases?*',r=>r.fulfill({json:{releases:[release],next_cursor:''}}));
 await page.route('**/v1/releases/release-a',r=>r.fulfill({json:{release,current_baseline:'43',baseline_warning:true,rollout:null}}));
 let posted:any;
 await page.route('**/v1/releases/release-a:deploy',r=>{posted=r.request().postDataJSON();return r.fulfill({json:{release:{...release,state:'DEPLOYED'}}});});
 await page.goto('/#/releases');await page.getByText('release-a · Approved',{exact:true}).click();
 const deploy=page.getByRole('button',{name:'Deploy approved release'});await expect(deploy).toBeDisabled();
 await page.getByRole('checkbox').check();await expect(deploy).toBeEnabled();await deploy.click();
 await expect.poll(()=>posted?.ack_baseline).toBe('43');
});
