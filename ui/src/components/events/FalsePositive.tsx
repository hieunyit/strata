import React, { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { ApiError, Event, MarkFalsePositiveRequest, MarkFalsePositiveResponse, apiClient } from '../../api/client';
import { canWriteEvents } from '../../auth/roles';
import { useAuth } from '../../context/AuthContext';

type Failure = 'conflict' | 'forbidden' | 'invalid' | 'uncertain';

export const FalsePositive: React.FC<{ event: Event; onReload: () => void }> = ({ event, onReload }) => {
  const { roles } = useAuth(), { t } = useTranslation();
  const [open, setOpen] = useState(false), [reason, setReason] = useState('');
  const [saving, setSaving] = useState(false), [error, setError] = useState<Failure>();
  const [receipt, setReceipt] = useState<MarkFalsePositiveResponse>();
  const mounted = useRef(false), posting = useRef(false), pending = useRef<MarkFalsePositiveRequest>();
  const wasOpen = useRef(false);
  const launch = useRef<HTMLButtonElement>(null), input = useRef<HTMLTextAreaElement>(null);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  useEffect(() => { if (open) input.current?.focus(); else if (wasOpen.current) launch.current?.focus(); wasOpen.current = open; }, [open]);
  const marked = event.false_positive || receipt?.false_positive;
  const valid = reason.trim() !== '' && !reason.includes('\0') && new TextEncoder().encode(reason.trim()).length <= 500;
  const frozen = saving || error === 'uncertain' || error === 'forbidden' || error === 'conflict';
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (posting.current || !valid || !canWriteEvents(roles) || error === 'forbidden' || error === 'conflict') return;
    posting.current = true; setSaving(true); setError(undefined);
    try {
      const command = pending.current ?? { reason: reason.trim(), etag: event.annotation_etag ?? '', request_id: crypto.randomUUID() };
      pending.current = command;
      const reply = await apiClient.markFalsePositive(event.block_id, command);
      if (reply.block_id !== event.block_id || reply.false_positive !== true || reply.reason !== command.reason ||
          !reply.etag || !reply.marked_by || !Number.isFinite(Date.parse(reply.marked_at))) throw new Error('invalid receipt');
      if (mounted.current) { setReceipt(reply); setOpen(false); }
    } catch (cause) {
      if (!mounted.current) return;
      if (cause instanceof ApiError && (cause.code === 409 || cause.code === 404)) setError('conflict');
      else if (cause instanceof ApiError && cause.code === 403) setError('forbidden');
      else if (cause instanceof ApiError && cause.code === 400) { pending.current = undefined; setError('invalid'); }
      else setError('uncertain');
    } finally {
      posting.current = false;
      if (mounted.current) setSaving(false);
    }
  };
  if (marked) return <section className="panel mb-4 p-4 text-sm" data-testid="false-positive-saved" role="status">
    <h2 className="font-medium">{t('falsePositive.marked')}</h2>
    <p className="mt-2 break-words">{receipt?.reason ?? event.false_positive_reason}</p>
    <p className="mt-1 text-muted">{t('falsePositive.by', { actor: receipt?.marked_by ?? event.false_positive_by, at: receipt?.marked_at ?? event.false_positive_at })}</p>
  </section>;
  if (!canWriteEvents(roles) || !['block', 'shadow'].includes(event.action)) return null;
  return <div className="mb-4">
    <button ref={launch} type="button" className="btn" disabled={open} aria-expanded={open} onClick={() => setOpen(true)}>{t('falsePositive.open')}</button>
    {open && <section className="panel mt-3 p-4" aria-labelledby="classification-heading">
      <h2 id="classification-heading" className="font-medium">{t('falsePositive.title')}</h2>
      <p className="mt-2 text-sm text-muted">{t('falsePositive.help')}</p>
      <form onSubmit={(e) => void submit(e)}>
        <label className="mt-3 block text-sm">{t('falsePositive.reason')}
          <textarea ref={input} className="field mt-1 min-h-20 w-full" maxLength={500} value={reason} disabled={frozen} onChange={(e) => setReason(e.target.value)} />
        </label>
        {reason.trim() && !valid && <p role="alert" className="mt-2 text-sm text-block">{t('falsePositive.limit')}</p>}
        {error && <p role="alert" className="mt-2 text-sm text-block">{t(`falsePositive.errors.${error}`)}</p>}
        {error === 'conflict' && <button type="button" className="btn mt-2" onClick={onReload}>{t('falsePositive.reload')}</button>}
        <div className="mt-3 flex gap-2">
          <button type="submit" className="btn-primary" disabled={saving || !valid || error === 'forbidden' || error === 'conflict'}>{t(saving ? 'falsePositive.saving' : error === 'uncertain' ? 'falsePositive.retry' : 'falsePositive.save')}</button>
          <button type="button" className="btn" disabled={saving || error === 'uncertain'} onClick={() => { setOpen(false); setError(undefined); }}>{t('falsePositive.cancel')}</button>
        </div>
      </form>
    </section>}
  </div>;
};
