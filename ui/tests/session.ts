import type { Page } from '@playwright/test';

// signedIn stores an oidc-client-ts session in sessionStorage before the
// app loads, so mocked-API tests start signed in. The token is not signed:
// the API is mocked too.
export async function signedIn(page: Page, roles: string[], username = 'lab-operator'): Promise<void> {
  const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const access = `${b64({ alg: 'none' })}.${b64({ realm_access: { roles }, preferred_username: username })}.x`;
  const user = {
    access_token: access,
    token_type: 'Bearer',
    scope: 'openid profile',
    profile: { sub: 'u-' + username, preferred_username: username },
    expires_at: Math.floor(Date.now() / 1000) + 3600,
  };
  await page.addInitScript((value) => {
    sessionStorage.setItem('oidc.user:http://127.0.0.1:18180/realms/strata:strata-ui', value);
  }, JSON.stringify(user));
  await page.route('**/v1/version', (route) =>
    route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ version: 'test', commit: '', api_version: 'v1' }) }),
  );
}
