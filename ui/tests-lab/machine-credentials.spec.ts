import { test, expect } from '@playwright/test';
import fs from 'fs';
import path from 'path';

test('machine token loss, retry, scope and revoke through real auth/API/PostgreSQL', async ({ page, baseURL }) => {
  const password=process.env.STRATA_MACHINE_LAB_PASSWORD, output=process.env.STRATA_MACHINE_EVIDENCE_DIR;
  if(!password || !output || !baseURL)throw new Error('Private machine fixture required');
  const external:string[]=[], errors:string[]=[], urlCredentials:string[]=[];
  const commands:unknown[]=[];
  page.on('pageerror',error=>errors.push(error.message));
  page.on('dialog',dialog=>void dialog.accept());
  page.on('request',request=>{
    const url=new URL(request.url());
    if(url.searchParams.has('token') || url.searchParams.has('access_token'))urlCredentials.push(url.pathname);
    if(request.method()==='POST' && /\/service-accounts\/[^/]+\/tokens$/.test(url.pathname))commands.push(request.postDataJSON());
  });
  await page.route('**/*',async route=>{
    const url=new URL(route.request().url());
    if(url.origin!==new URL(baseURL).origin){external.push(url.origin);await route.abort();return;}
    await route.continue();
  });
  const login=async(role:string)=>{
    await page.getByTestId('login-username').fill(`example-${role}`);
    await page.getByTestId('login-password').fill(password);
    await page.getByTestId('password-login-btn').click();
    await expect(page.getByTestId('logout-btn')).toBeVisible();
  };
  await page.goto('/#/users');await login('admin');
  await page.getByTestId('tab-service-accounts').click();
  await expect(page.getByTestId('sa-empty')).toBeVisible();
  await page.getByTestId('new-sa-btn').click();
  await page.getByTestId('sa-name').fill('example-browser');
  await page.getByTestId('sa-description').fill('Private browser acceptance');
  await page.getByTestId('machine-role-admin').check();
  const accountResponse=page.waitForResponse(r=>r.url().endsWith('/v1/service-accounts') && r.request().method()==='POST');
  await page.getByTestId('create-sa-submit').click();
  expect((await accountResponse).status()).toBe(201);
  const manage=page.getByTestId('manage-tokens-btn');
  await manage.click();
  const dialog=page.getByRole('dialog');
  await expect(dialog).toBeVisible();
  await dialog.getByRole('checkbox',{name:'policies:read',exact:true}).uncheck();
  let dropped=false,committedStatus=0;
  await page.route('**/v1/service-accounts/*/tokens',async route=>{
    const url=new URL(route.request().url());
    if(url.origin!==new URL(baseURL).origin){external.push(url.origin);await route.abort();return;}
    if(route.request().method()==='POST' && !dropped){
      dropped=true;const response=await route.fetch();committedStatus=response.status();await route.abort();return;
    }
    await route.fallback();
  });
  await page.getByTestId('generate-token-btn').click();
  const retryButton=dialog.getByRole('button',{name:'Retry the same command',exact:true});
  await expect(retryButton).toBeEnabled();expect(committedStatus).toBe(201);
  const retryResponse=page.waitForResponse(r=>/\/service-accounts\/[^/]+\/tokens$/.test(new URL(r.url()).pathname) && r.request().method()==='POST' && r.status()===200);
  await retryButton.click();
  const retry=await(await retryResponse).json();
  expect(retry.replayed===true && !('raw_token' in retry)).toBe(true);
  await expect(page.getByTestId('machine-token-receipt')).toContainText('Its secret cannot be shown again');
  expect(JSON.stringify(commands[0])===JSON.stringify(commands[1])).toBe(true);
  const firstRow=dialog.locator('li').filter({hasText:retry.token.id});
  const revokeFirst=page.waitForResponse(r=>r.request().method()==='DELETE' && r.url().endsWith('/tokens/'+retry.token.id));
  await firstRow.getByRole('button',{name:'Revoke',exact:true}).click();
  expect((await revokeFirst).status()).toBe(204);
  await expect(firstRow).toContainText('Revoked');
  const issueSecond=page.waitForResponse(r=>r.request().method()==='POST' && /\/service-accounts\/[^/]+\/tokens$/.test(new URL(r.url()).pathname) && r.status()===201);
  await page.getByTestId('generate-token-btn').click();expect((await issueSecond).status()).toBe(201);
  const secretInput=dialog.getByLabel('Token secret',{exact:true});
  await secretInput.waitFor();
  let secret=await secretInput.inputValue();
  expect(secret.startsWith('stsa_') && secret.length===53).toBe(true);
  expect(await secretInput.evaluate(e=>(e as HTMLInputElement).type==='password')).toBe(true);
  const secondID=(await dialog.getByTestId('machine-token-receipt').locator('p.font-mono').textContent())!;
  const scope=await page.evaluate(async token=>{
    const headers={Authorization:`Bearer ${token}`,'Content-Type':'application/json'};
    try{
      const read=await fetch('/v1/events:search',{method:'POST',headers,body:JSON.stringify({page_size:1})});
      const write=await fetch('/v1/service-accounts',{method:'POST',headers,body:JSON.stringify({id:'example-must-deny',name:'Denied',request_id:crypto.randomUUID()})});
      return {read:read.status,write:write.status};
    }catch{return {read:-1,write:-1};}
  },secret);
  expect(scope).toEqual({read:200,write:403});
  await page.keyboard.press('Escape');await expect(dialog).toHaveCount(0);
  await expect(manage).toBeFocused();await expect(manage).toContainText('Tokens (1)');
  await page.setViewportSize({width:390,height:844});
  await page.getByTestId('language-toggle-btn').click();
  await manage.click();await expect(dialog).toBeVisible();
  const bounds=await dialog.boundingBox();
  expect(!!bounds && bounds.x>=0 && bounds.x+bounds.width<=390).toBe(true);
  expect(await page.getByLabel('Khóa token',{exact:true}).count()).toBe(0);
  const secondRow=dialog.locator('li').filter({hasText:secondID});
  const revokeSecond=page.waitForResponse(r=>r.request().method()==='DELETE' && r.url().endsWith('/tokens/'+secondID));
  await secondRow.getByRole('button',{name:'Thu hồi',exact:true}).click();expect((await revokeSecond).status()).toBe(204);
  const revoked=await page.evaluate(async token=>{
    try{return(await fetch('/v1/auth/me',{headers:{Authorization:`Bearer ${token}`}})).status;}catch{return -1;}
  },secret);secret='';expect(revoked).toBe(401);
  await page.keyboard.press('Escape');await expect(dialog).toHaveCount(0);
  await expect(manage).toContainText('Token (0)');
  await page.screenshot({path:path.join(output,'machine-mobile-vi.png'),fullPage:true});
  const remove=page.waitForResponse(r=>r.request().method()==='DELETE' && !r.url().includes('/tokens/'));
  await page.getByTestId('delete-sa-btn').click();expect((await remove).status()).toBe(204);
  await expect(page.getByTestId('sa-empty')).toBeVisible();
  const denied:Record<string,number>={};
  for(const role of ['viewer','approver']){
    await page.getByTestId('logout-btn').click();await login(role);
    await expect(page.getByTestId('tab-service-accounts')).toHaveCount(0);
    denied[role]=await page.evaluate(async()=>{
      const session=JSON.parse(sessionStorage.getItem('strata.localSession')??'{}');
      try{return(await fetch('/v1/service-accounts',{method:'POST',headers:{Authorization:`Bearer ${session.token}`,'Content-Type':'application/json'},body:JSON.stringify({id:'example-denied',name:'Denied',request_id:crypto.randomUUID()})})).status;}catch{return -1;}
    });
    expect(denied[role]).toBe(403);
  }
  expect(commands.length).toBe(3);expect(errors).toEqual([]);expect(external).toEqual([]);expect(urlCredentials).toEqual([]);
  fs.writeFileSync(path.join(output,'browser-result.json'),JSON.stringify({lost_response_after_commit:true,identical_retry:true,token_posts:commands.length,scope,revoked_status:revoked,denied,mobile_bounds:bounds,errors,external,url_credentials:urlCredentials,scope_note:'real local auth/API/PostgreSQL; no secret/trace recorded; no NGINX/deploy/production'},null,2)+'\n');
});
