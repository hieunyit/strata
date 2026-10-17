import React, { useCallback, useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { ApiError, Event, ExceptionDraftResponse, ExceptionFromBlockRequest, GetEventResponse, Policy, apiClient } from '../../api/client';
import { canWritePolicies } from '../../auth/roles';
import { useAuth } from '../../context/AuthContext';
import { href } from '../../router';

type Scope = { rule_id: number; field: string };
type Failure = 'load' | 'conflict' | 'invalid' | 'forbidden' | 'uncertain';

const DraftForm: React.FC<{ event: Event; scopes: Scope[]; onClose: () => void }> = ({ event, scopes, onClose }) => {
  const { t } = useTranslation();
  const [policy, setPolicy] = useState<Policy>();
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<Failure>();
  const [selected, setSelected] = useState(0);
  const [reason, setReason] = useState('');
  const [ttl, setTtl] = useState(3600);
  const [result, setResult] = useState<ExceptionDraftResponse>();
  const alive = useRef(false), read = useRef(0), posting = useRef(false);
  // An ambiguous write is retried with exactly the original command and ID.
  const pending = useRef<ExceptionFromBlockRequest>();
  const reasonInput = useRef<HTMLTextAreaElement>(null);
  const load = useCallback(async () => {
    const epoch = ++read.current;
    setLoading(true); setPolicy(undefined); setError(undefined); pending.current = undefined;
    try {
      const matches = (await apiClient.listPolicies()).filter((p) => p.name === event.policy_id);
      if (!alive.current || epoch !== read.current) return;
      if (matches.length !== 1 || !matches[0].id || !matches[0].etag) throw new Error('unavailable');
      setPolicy(matches[0]);
    } catch {
      if (alive.current && epoch === read.current) setError('load');
    } finally {
      if (alive.current && epoch === read.current) setLoading(false);
    }
  }, [event.policy_id]);
  useEffect(() => { alive.current = true; void load(); reasonInput.current?.focus(); return () => { alive.current = false; }; }, [load]);

  const validReason = reason.trim() !== '' && !reason.includes('\0') && new TextEncoder().encode(reason.trim()).length <= 500;
  const frozen = saving || error === 'uncertain' || error === 'forbidden';
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (posting.current || !policy?.etag || !scopes[selected] || !validReason || error === 'forbidden') return;
    posting.current = true; setSaving(true); setError(undefined);
    try {
      const command = pending.current ?? {
        block_id: event.block_id, ...scopes[selected], reason: reason.trim(), ttl_seconds: ttl,
        etag: policy.etag, request_id: crypto.randomUUID(),
      };
      pending.current = command;
      const reply = await apiClient.createExceptionFromBlock(command);
      if (reply.state !== 'DRAFT' || reply.policy_id !== policy.id || !Number.isSafeInteger(reply.policy_version) || reply.policy_version < 1 ||
          reply.exception?.rule_id !== command.rule_id || reply.exception?.field !== command.field) throw new Error('invalid receipt');
      if (alive.current) setResult(reply);
    } catch (cause) {
      if (!alive.current) return;
      if (cause instanceof ApiError && (cause.code === 409 || cause.code === 404)) {
        setPolicy(undefined); setError('conflict');
      } else if (cause instanceof ApiError && cause.code === 400) {
        pending.current = undefined; setError('invalid');
      } else setError(cause instanceof ApiError && cause.code === 403 ? 'forbidden' : 'uncertain');
    } finally {
      posting.current = false;
      if (alive.current) setSaving(false);
    }
  };

  return <section className="panel mb-5 p-4" aria-labelledby="exception-heading" data-testid="exception-form"
    onKeyDown={(e) => { if (e.key === 'Escape' && !saving) onClose(); }}>
    <h2 id="exception-heading" className="font-medium">{t('exception.title')}</h2>
    {result ? <div role="status" className="mt-3 text-sm" data-testid="exception-created">
      <p>{t('exception.created', { version: result.policy_version })}</p>
      <p className="mt-2 text-muted">{t('exception.reviewRequired')}</p>
      <a href={href({ page: 'policies' })} className="btn mt-3">{t('exception.viewPolicies')}</a>
      <button type="button" className="btn ml-2" onClick={onClose}>{t('exception.close')}</button>
    </div> : <form onSubmit={(e) => void submit(e)}>
      <p className="my-2 text-sm text-muted">{t('exception.scopeHelp')}</p>
      <dl className="text-sm break-words" data-testid="exception-route">
        <dt className="text-muted">{t('exception.route')}</dt><dd>{event.http_method} {event.http_host}{event.http_path}</dd>
      </dl>
      {policy && <p className="mt-2 text-sm text-muted">{t('exception.policyVersion', { name: policy.name, version: policy.version ?? '?' })}</p>}
      <div className="mt-3 grid gap-3 sm:grid-cols-2">
        <label className="min-w-0 text-sm">{t('exception.scope')}
          <select className="field mt-1 w-full" value={selected} disabled={frozen} onChange={(e) => setSelected(Number(e.target.value))}>
            {scopes.map((scope, i) => <option key={JSON.stringify(scope)} value={i}>{scope.rule_id} · {scope.field}</option>)}
          </select>
        </label>
        <label className="min-w-0 text-sm">{t('exception.duration')}
          <select className="field mt-1 w-full" value={ttl} disabled={frozen} onChange={(e) => setTtl(Number(e.target.value))}>
            {[3600, 86400, 604800, 2592000].map((value) => <option key={value} value={value}>{t(`exception.ttl.${value}`)}</option>)}
          </select>
        </label>
      </div>
      <label className="mt-3 block text-sm">{t('exception.reason')}
        <textarea ref={reasonInput} className="field mt-1 min-h-20 w-full py-2" value={reason} maxLength={500} disabled={frozen} onChange={(e) => setReason(e.target.value)} />
      </label>
      {reason.trim() && !validReason && <p role="alert" className="mt-2 text-sm text-block">{t('exception.reasonLimit')}</p>}
      {loading && <p role="status" className="mt-2 text-sm">{t('exception.loading')}</p>}
      {error && <p role="alert" className="mt-2 text-sm text-block">{t(`exception.errors.${error}`)}</p>}
      {(error === 'load' || error === 'conflict') && <button type="button" className="btn mt-2" disabled={loading} onClick={() => void load()}>{t('exception.reload')}</button>}
      <div className="mt-4 flex gap-2">
        <button type="submit" className="btn-primary" disabled={loading || saving || !policy || !validReason || error === 'forbidden'}>
          {t(saving ? 'exception.saving' : error === 'uncertain' ? 'exception.retry' : 'exception.create')}
        </button>
        <button type="button" className="btn" disabled={saving} onClick={onClose}>{t('exception.cancel')}</button>
      </div>
    </form>}
  </section>;
};

export const ExceptionDraft: React.FC<{ event: Event; rules?: GetEventResponse['rules'] }> = ({ event, rules }) => {
  const { roles } = useAuth();
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const launch = useRef<HTMLButtonElement>(null), wasOpen = useRef(false);
  useEffect(() => { if (!open && wasOpen.current) launch.current?.focus(); wasOpen.current = open; }, [open]);
  if (!canWritePolicies(roles) || event.action !== 'block' || !event.block_id.startsWith('STR-')) return null;
  const scopes = (event.violations ?? []).filter((v, i, all) => rules?.[String(v.rule_id)]?.layer === 'managed' &&
    /^(ARGS|REQUEST_HEADERS):[^*]+$/.test(v.field) && !v.field.endsWith('|base64') &&
    all.findIndex((other) => other.rule_id === v.rule_id && other.field === v.field) === i).map(({ rule_id, field }) => ({ rule_id, field }));
  return <>
    <button ref={launch} type="button" className="btn mb-3" disabled={open || scopes.length === 0} aria-expanded={open} onClick={() => setOpen(true)}>{t('exception.open')}</button>
    {scopes.length === 0 && <p className="mb-3 text-sm text-muted">{t('exception.noScope')}</p>}
    {open && <DraftForm event={event} scopes={scopes} onClose={() => setOpen(false)} />}
  </>;
};
