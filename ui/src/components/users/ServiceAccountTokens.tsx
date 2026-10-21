import React, { useCallback, useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { apiClient, ApiError, ServiceAccount, ServiceAccountToken, CreateTokenResponse, CreateServiceAccountTokenRequest } from '../../api/client';
import { ErrorBanner, formatTime } from '../ui';
const SCOPES = ['discovery:ingest', 'applications:read', 'version:read', 'events:read', 'events:read_sensitive', 'policies:read', 'policies:write', 'policies:approve', 'policies:deploy', 'rules:disable', 'nodes:read', 'nodes:write', 'rolebindings:read', 'rolebindings:write', 'serviceaccounts:read', 'serviceaccounts:write', 'audit:read', 'replay:configure', 'exceptions:write'] as const;
export const ServiceAccountTokens: React.FC<{
    sa: ServiceAccount;
    onClose: () => void;
}> = ({ sa, onClose }) => {
    const { t, i18n } = useTranslation();
    const [tokens, setTokens] = useState<ServiceAccountToken[]>([]);
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(true);
    const [scopes, setScopes] = useState<CreateServiceAccountTokenRequest['scopes']>(['policies:read', 'events:read']);
    const [days, setDays] = useState(30);
    const [receipt, setReceipt] = useState<CreateTokenResponse>();
    const [busy, setBusy] = useState(false);
    const [revealed,setRevealed]=useState(false);
    const [copied,setCopied]=useState(false);
    const [pending, setPending] = useState(false);
    const inFlight = useRef(false);
    const issue = useRef<CreateServiceAccountTokenRequest>();
    const dialog=useRef<HTMLElement>(null);
    const close=useRef(onClose);
    close.current=onClose;
    useEffect(()=>{
        const previous=document.activeElement instanceof HTMLElement?document.activeElement:undefined;
        dialog.current?.querySelector<HTMLButtonElement>('button')?.focus();
        const keydown=(event:KeyboardEvent)=>{
            if(event.key==='Escape'){
                event.preventDefault();event.stopPropagation();
                if(!inFlight.current)close.current();
            }
            if(event.key!=='Tab' || !dialog.current)return;
            const controls=Array.from(dialog.current.querySelectorAll<HTMLElement>('button,input,select,textarea,a[href],[tabindex]'))
                .filter(element=>!element.matches(':disabled') && element.tabIndex>=0);
            if(!controls.length){event.preventDefault();dialog.current.focus();return;}
            const first=controls[0],last=controls[controls.length-1];
            if(!dialog.current.contains(document.activeElement)){
                event.preventDefault();(event.shiftKey?last:first).focus();
            }else if(event.shiftKey && document.activeElement===first){event.preventDefault();last.focus();}
            else if(!event.shiftKey && document.activeElement===last){event.preventDefault();first.focus();}
        };
        document.addEventListener('keydown',keydown);
        return()=>{document.removeEventListener('keydown',keydown);if(previous?.isConnected)previous.focus();};
    },[]);

    const revokes = useRef(new Map<string, {
        etag: string;
        requestId: string;
    }>());
    const readVersion=useRef(0);
    const load = useCallback(async () => {
        const version=++readVersion.current;
        setLoading(true);
        try {
            const result=await apiClient.listServiceAccountTokens(sa.id);
            if(version===readVersion.current)setTokens(result);
        }
        catch (e) {
            if(version===readVersion.current)setError(e instanceof Error ? e.message : String(e));
        }
        finally {
            if(version===readVersion.current)setLoading(false);
        }
    }, [sa.id]);
    useEffect(() => { void load(); return()=>{readVersion.current++;}; }, [load]);
    const generate = async (e: React.FormEvent) => {
        e.preventDefault();
        if (inFlight.current)
            return;
        inFlight.current = true;
        setBusy(true);
        setError('');
        setReceipt(undefined);
        setRevealed(false);setCopied(false);
        try {
            issue.current ??= { scopes: [...scopes], ttl_seconds: days * 86400, request_id: crypto.randomUUID(), etag: sa.etag };
            setPending(true);
            const res = await apiClient.createServiceAccountToken(sa.id, issue.current);
            if (!res?.token || !Array.isArray(res.token.scopes) ||
                typeof res.token.id !== 'string' || typeof res.token.etag !== 'string' ||
                typeof res.token.expires_at !== 'string' || typeof res.token.created_at !== 'string' ||
                (res.replayed !== undefined && typeof res.replayed !== 'boolean') ||
                (!res.replayed && typeof res.raw_token !== 'string')) {
                throw new Error(t('machine.invalidReceipt'));
            }
            const expected = issue.current;
            const duration = Date.parse(res.token.expires_at) - Date.parse(res.token.created_at);
            if (res.token.service_account_id !== sa.id || !res.token.id || !res.token.etag ||
                JSON.stringify([...res.token.scopes].sort()) !== JSON.stringify([...expected.scopes].sort()) ||
                duration !== (expected.ttl_seconds ?? 2592000) * 1000 ||
                (!res.replayed && !res.raw_token) || (res.replayed && !!res.raw_token))
                throw new Error(t('machine.invalidReceipt'));
            setReceipt(res);
            issue.current = undefined;
            setPending(false);
            void load();
        }
        catch (e) {
            setError(e instanceof Error ? e.message : String(e));
            if (e instanceof ApiError && e.code === 400) {
                issue.current = undefined;
                setPending(false);
            }
        }
        finally {
            inFlight.current = false;
            setBusy(false);
        }
    };
    const revoke = async (token: ServiceAccountToken) => {
        if (inFlight.current || !window.confirm(t('machine.revokeConfirm')))
            return;
        inFlight.current = true;
        setBusy(true);
        setError('');
        try {
            let cmd = revokes.current.get(token.id);
            if (!cmd) {
                cmd = { etag: token.etag, requestId: crypto.randomUUID() };
                revokes.current.set(token.id, cmd);
            }
            await apiClient.revokeServiceAccountToken(sa.id, token.id, cmd.etag, cmd.requestId);
            revokes.current.delete(token.id);
            void load();
        }
        catch (e) {
            setError(e instanceof Error ? e.message : String(e));
        }
        finally {
            inFlight.current = false;
            setBusy(false);
        }
    };
    const copySecret=async()=>{
        if(!receipt?.raw_token)return;
        try{await navigator.clipboard.writeText(receipt.raw_token);setCopied(true);}
        catch{setError(t('machine.copyFailed'));}
    };
    return <div className="fixed inset-0 z-50 flex items-center justify-center bg-ink/40 p-4">
    <section ref={dialog} tabIndex={-1} role="dialog" aria-modal="true" aria-labelledby="machine-token-title" className="panel max-h-[90vh] w-full max-w-2xl overflow-auto p-5 space-y-4">
      <div className="flex justify-between gap-3"><h2 id="machine-token-title" className="min-w-0 break-words">{t('machine.tokensFor', { name: sa.name })}</h2>
        <button type="button" className="btn shrink-0" onClick={onClose} disabled={busy}>{t('machine.close')}</button></div>
      <ErrorBanner message={error}/>
      {receipt && <div className="panel p-3" data-testid="machine-token-receipt">
        <p>{t(receipt.replayed ? 'machine.secretUnavailable' : 'machine.secretOnce')}</p>
        <p className="font-mono break-all">{receipt.token.id}</p>
        {receipt.raw_token && <div className="space-y-2">
          <input type={revealed?'text':'password'} autoComplete="off" className="field font-mono" readOnly aria-label={t('machine.secret')} value={receipt.raw_token}/>
          <div className="flex gap-2">
            <button type="button" className="btn" aria-pressed={revealed} onClick={()=>setRevealed(v=>!v)}>{t(revealed?'machine.hide':'machine.show')}</button>
            <button type="button" className="btn" onClick={()=>void copySecret()}>{t(copied?'machine.copied':'machine.copy')}</button>
          </div>
        </div>}
      </div>}
      <form onSubmit={generate} className="space-y-3" data-testid="generate-token-form">
        <p className="text-xs text-muted">{t('machine.scopeCeiling')}</p>
        <fieldset disabled={busy || pending} className="space-y-2"><legend>{t('machine.scopes')}</legend>
          <div className="grid grid-cols-2 gap-2 text-xs">{SCOPES.map(scope => <label key={scope}><input type="checkbox" checked={scopes.includes(scope)} onChange={e => setScopes(e.target.checked ? [...scopes, scope] : scopes.filter(s => s !== scope))}/> {scope}</label>)}</div>
          <label htmlFor="machine-ttl">{t('machine.ttl')}</label>
          <select id="machine-ttl" className="field" value={days} onChange={e => setDays(Number(e.target.value))}>
            {[7, 30, 90, 365].map(n => <option key={n} value={n}>{t('machine.days', { count: n })}</option>)}
          </select>
        </fieldset>
        <button type="submit" className="btn-primary" disabled={busy || !scopes.length} data-testid="generate-token-btn">{t(busy?'machine.working':pending ? 'machine.retry' : 'machine.generate')}</button>
      </form>
      {loading ? <p>{t('machine.loading')}</p> : <ul className="space-y-2">{tokens.map(token => <li key={token.id} className="panel p-2 break-all">
        <p className="font-mono">{token.token_prefix} · {token.id}</p><p>{token.scopes.join(', ')}</p>
        <p>{token.revoked ? t('machine.revoked') : formatTime(token.expires_at, i18n.language, t('users.never'))}</p>
        {!token.revoked && <button className="btn" type="button" disabled={busy} onClick={() => void revoke(token)}>{t('machine.revoke')}</button>}
      </li>)}</ul>}
      {!loading && !tokens.length && <p>{t('machine.emptyTokens')}</p>}
    </section>
  </div>;
};
