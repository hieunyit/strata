import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { ServiceAccountTokens } from '../components/users/ServiceAccountTokens';
import { apiClient, ApiError, ServiceAccount, ServiceAccountToken } from '../api/client';
import i18n from '../i18n';
const account: ServiceAccount = { id: 'example-machine', etag: 'account-etag', name: 'Example', roles: ['viewer'], created_at: '2026-10-18T00:00:00Z', created_by: 'example-admin' };
const token: ServiceAccountToken = { id: 'example-token', etag: 'token-etag', service_account_id: account.id, token_prefix: 'stsa_example', scopes: ['policies:read', 'events:read'], expires_at: '2026-11-17T00:00:00Z', created_at: '2026-10-18T00:00:00Z', revoked: false };
beforeEach(async () => { await i18n.changeLanguage('en'); vi.spyOn(apiClient, 'listServiceAccountTokens').mockResolvedValue([]); });
afterEach(() => { vi.restoreAllMocks(); });
describe('durable one-time machine token workflow', () => {
    it('retries the exact command after an uncertain response and explains lost plaintext', async () => {
        const issue = vi.spyOn(apiClient, 'createServiceAccountToken').mockRejectedValueOnce(new ApiError('uncertain result', 503)).mockResolvedValueOnce({ token, replayed: true });
        render(<ServiceAccountTokens sa={account} onClose={() => { }}/>);
        fireEvent.submit(screen.getByTestId('generate-token-form'));
        await screen.findByText('uncertain result');
        expect(screen.getByRole('checkbox', { name: 'events:read' })).toBeDisabled();
        fireEvent.submit(screen.getByTestId('generate-token-form'));
        await screen.findByTestId('machine-token-receipt');
        expect(issue).toHaveBeenCalledTimes(2);
        expect(issue.mock.calls[1]).toEqual(issue.mock.calls[0]);
        expect(issue.mock.calls[0][1]).toMatchObject({ etag: account.etag, scopes: ['policies:read', 'events:read'] });
        expect(issue.mock.calls[0][1].request_id).toBeTruthy();
        expect(screen.getByText(/Its secret cannot be shown again/)).toBeInTheDocument();
        expect(screen.queryByLabelText('Token secret')).not.toBeInTheDocument();
    });
    it('serializes submissions and only displays a bound successful receipt', async () => {
        let finish!: (v: {
            token: ServiceAccountToken;
            raw_token: string;
        }) => void;
        const issue = vi.spyOn(apiClient, 'createServiceAccountToken').mockReturnValue(new Promise(resolve => { finish = resolve; }));
        render(<ServiceAccountTokens sa={account} onClose={() => { }}/>);
        const form = screen.getByTestId('generate-token-form');
        fireEvent.submit(form);
        fireEvent.submit(form);
        expect(issue).toHaveBeenCalledTimes(1);
        finish({ token, raw_token: 'example-one-time-secret' });
        await waitFor(() => expect(screen.getByLabelText('Token secret')).toHaveValue('example-one-time-secret'));
        expect(screen.getByText('Copy this secret now. It is shown only once.')).toBeInTheDocument();
    });
    it('refuses a receipt belonging to another account', async () => {
        vi.spyOn(apiClient, 'createServiceAccountToken').mockResolvedValue({ token: { ...token, service_account_id: 'other-account' }, raw_token: 'wrong-secret' });
        render(<ServiceAccountTokens sa={account} onClose={() => { }}/>);
        fireEvent.submit(screen.getByTestId('generate-token-form'));
        await screen.findByText(/Invalid token receipt/);
        expect(screen.queryByDisplayValue('wrong-secret')).not.toBeInTheDocument();
    });
    it('pins a revoke to the metadata viewed and reuses its command after failure', async () => {
        vi.spyOn(apiClient, 'listServiceAccountTokens').mockResolvedValue([token]);
        vi.spyOn(window, 'confirm').mockReturnValue(true);
        const revoke = vi.spyOn(apiClient, 'revokeServiceAccountToken').mockRejectedValueOnce(new ApiError('uncertain revoke', 503)).mockResolvedValueOnce();
        render(<ServiceAccountTokens sa={account} onClose={() => { }}/>);
        fireEvent.click(await screen.findByRole('button', { name: 'Revoke' }));
        await screen.findByText('uncertain revoke');
        fireEvent.click(screen.getByRole('button', { name: 'Revoke' }));
        await waitFor(() => expect(revoke).toHaveBeenCalledTimes(2));
        expect(revoke.mock.calls[1]).toEqual(revoke.mock.calls[0]);
        expect(revoke.mock.calls[0].slice(0, 3)).toEqual([account.id, token.id, token.etag]);
    });
    it('traps keyboard focus and closes with Escape',async()=>{
        const close=vi.fn();
        render(<ServiceAccountTokens sa={account} onClose={close}/>);
        const button=screen.getByRole('button',{name:'Close'});
        expect(button).toHaveFocus();
        fireEvent.keyDown(document,{key:'Tab',shiftKey:true});
        expect(screen.getByTestId('generate-token-btn')).toHaveFocus();
        fireEvent.keyDown(document,{key:'Tab'});expect(button).toHaveFocus();
        fireEvent.keyDown(document,{key:'Escape'});expect(close).toHaveBeenCalledOnce();
    });
    it('ignores a stale list response arriving after issuance',async()=>{
        let finish!:(tokens:ServiceAccountToken[])=>void;
        vi.spyOn(apiClient,'listServiceAccountTokens').mockReturnValueOnce(new Promise(resolve=>{finish=resolve;})).mockResolvedValue([token]);
        vi.spyOn(apiClient,'createServiceAccountToken').mockResolvedValue({token,raw_token:'example-one-time-secret'});
        render(<ServiceAccountTokens sa={account} onClose={()=>{}}/>);
        fireEvent.submit(screen.getByTestId('generate-token-form'));
        await screen.findByRole('button',{name:'Revoke'});
        await act(async()=>{finish([]);await Promise.resolve();});
        expect(screen.getByRole('button',{name:'Revoke'})).toBeInTheDocument();
    });
    it('keeps the secret masked and reports failed copying',async()=>{
        const descriptor=Object.getOwnPropertyDescriptor(navigator,'clipboard');
        Object.defineProperty(navigator,'clipboard',{configurable:true,value:{writeText:vi.fn().mockRejectedValue(new Error('example permission denied'))}});
        try{
            vi.spyOn(apiClient,'createServiceAccountToken').mockResolvedValue({token,raw_token:'example-one-time-secret'});
            render(<ServiceAccountTokens sa={account} onClose={()=>{}}/>);
            fireEvent.submit(screen.getByTestId('generate-token-form'));
            const input=await screen.findByLabelText('Token secret');expect(input).toHaveAttribute('type','password');
            fireEvent.click(screen.getByRole('button',{name:'Copy secret'}));
            await screen.findByText('Could not copy. Reveal and copy the secret manually before closing.');
            expect(screen.queryByRole('button',{name:'Copied'})).not.toBeInTheDocument();
            fireEvent.click(screen.getByRole('button',{name:'Show secret'}));expect(input).toHaveAttribute('type','text');
        }finally{
            if(descriptor)Object.defineProperty(navigator,'clipboard',descriptor);
            else Reflect.deleteProperty(navigator,'clipboard');
        }
    });

});
