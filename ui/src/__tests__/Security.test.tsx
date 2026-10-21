import {afterEach,describe,expect,it,vi} from 'vitest';
import {fireEvent,render,screen,waitFor} from '@testing-library/react';
import '../i18n';
import {SecurityPage} from '../pages/SecurityPage';
import {LoginPage} from '../pages/LoginPage';
import {AuthProvider,StaticAuthProvider} from '../context/AuthContext';
import {apiClient} from '../api/client';

afterEach(()=>{vi.restoreAllMocks();vi.unstubAllGlobals();});
describe('local account protection',()=>{
 it('confirms enrollment, shows recovery codes once and revokes only the chosen session',async()=>{
  vi.spyOn(apiClient,'localMfa').mockResolvedValueOnce({available:true,enabled:false,etag:'',recovery_remaining:0}).mockResolvedValueOnce({available:true,enabled:false,etag:'pending',recovery_remaining:0}).mockResolvedValue({available:true,enabled:true,etag:'enabled',recovery_remaining:8});
  vi.spyOn(apiClient,'ownSessions').mockResolvedValue({sessions:[{id:'other-session',etag:'other-session',current:false,mfa_verified:false,created_at:new Date().toISOString(),expires_at:new Date(Date.now()+3600000).toISOString()}]});
  vi.spyOn(apiClient,'beginMfa').mockResolvedValue({secret:'EXAMPLE-ENROLLMENT-SEED',uri:'otpauth://totp/example',etag:'pending',expires_at:new Date(Date.now()+600000).toISOString()});
  const confirm=vi.spyOn(apiClient,'confirmMfa').mockResolvedValue({recovery_codes:['EXAMPLE-RECOVERY-1','EXAMPLE-RECOVERY-2']});
  const revoke=vi.spyOn(apiClient,'revokeOwnSession').mockResolvedValue();
  render(<StaticAuthProvider roles={['viewer']} isLocal methods={{local:true,oidc:false}}><SecurityPage/></StaticAuthProvider>);
  await screen.findByRole('button',{name:'Set up authenticator'});
  fireEvent.change(screen.getByLabelText('Current password'),{target:{value:'example current password'}});
  fireEvent.click(screen.getByRole('button',{name:'Set up authenticator'}));
  expect(await screen.findByTestId('mfa-enrollment')).toHaveTextContent('EXAMPLE-ENROLLMENT-SEED');
  fireEvent.change(screen.getByLabelText('Authenticator code'),{target:{value:'123456'}});
  fireEvent.click(screen.getByRole('button',{name:'Confirm and enable'}));
  expect(await screen.findByTestId('recovery-codes')).toHaveTextContent('EXAMPLE-RECOVERY-1');
  expect(confirm).toHaveBeenCalledWith(expect.objectContaining({etag:'pending',code:'123456'}));
  expect(screen.queryByTestId('mfa-enrollment')).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button',{name:/I saved the codes/}));
  expect(screen.queryByText('EXAMPLE-RECOVERY-1')).not.toBeInTheDocument();
  await waitFor(()=>expect(screen.getByRole('button',{name:'Sign out session'})).not.toBeDisabled());
  fireEvent.click(screen.getByRole('button',{name:'Sign out session'}));
  await waitFor(()=>expect(revoke).toHaveBeenCalledWith('other-session','other-session'));
 });
 it('keeps MFA controls unavailable for an OIDC account',()=>{
  render(<StaticAuthProvider roles={['admin']}><SecurityPage/></StaticAuthProvider>);
  expect(screen.getByText(/Manage sign-in security at your identity provider/)).toBeInTheDocument();
  expect(screen.queryByLabelText('Current password')).not.toBeInTheDocument();
 });
 it('asks for the second factor without creating a session or placing credentials in a URL',async()=>{
  const requests:{url:string;body:Record<string,unknown>}[]=[];
  vi.stubGlobal('fetch',vi.fn(async(input:RequestInfo|URL,init?:RequestInit)=>{
   const url=String(input);
   if(url.endsWith('/auth/methods'))return new Response(JSON.stringify({local:true,oidc:false}),{status:200});
   if(url.endsWith('/auth/login')){requests.push({url,body:JSON.parse(String(init?.body))});return new Response(JSON.stringify({error:'Second factor required',code:401,reason:'MFA_REQUIRED'}),{status:401});}
   return new Response('{}',{status:404});
  }));
  render(<AuthProvider><LoginPage/></AuthProvider>);
  fireEvent.change(await screen.findByTestId('login-username'),{target:{value:'example-admin'}});
  fireEvent.change(screen.getByTestId('login-password'),{target:{value:'example-password'}});
  fireEvent.click(screen.getByTestId('password-login-btn'));
  expect(await screen.findByTestId('login-code')).toBeInTheDocument();
  expect(screen.getByTestId('login-password')).toHaveValue('example-password');
  fireEvent.change(screen.getByTestId('login-code'),{target:{value:'EXAMPLE-RECOVERY'}});
  fireEvent.click(screen.getByLabelText('Use a recovery code'));
  fireEvent.click(screen.getByTestId('password-login-btn'));
  await waitFor(()=>expect(requests).toHaveLength(2));
  expect(requests[1].body).toMatchObject({username:'example-admin',password:'example-password',code:'EXAMPLE-RECOVERY',recovery:true});
  expect(requests.every(r=>r.url==='/v1/auth/login')).toBe(true);
 });
});
