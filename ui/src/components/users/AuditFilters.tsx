import React, { useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { AuditQuery } from '../../api/client';

const empty = { actor: '', resource: '', action: '', channel: '', from: '', to: '' };

export function AuditFilters({ onApply }: { onApply: (query: AuditQuery) => void }) {
  const { t } = useTranslation();
  const [draft, setDraft] = useState(empty);
  const [invalid, setInvalid] = useState(false);
  const apply = (e: React.FormEvent) => {
    e.preventDefault();
    const query: AuditQuery = { limit: 200 };
    for (const key of ['actor', 'resource', 'action', 'channel'] as const) {
      if (draft[key]) query[key] = draft[key];
    }
    for (const key of ['from', 'to'] as const) {
      if (draft[key]) {
        const date = new Date(draft[key]);
        if (!Number.isFinite(date.getTime())) { setInvalid(true); return; }
        query[key] = date.toISOString();
      }
    }
    if (query.from && query.to && Date.parse(query.from) >= Date.parse(query.to)) { setInvalid(true); return; }
    setInvalid(false);
    onApply(query);
  };
  return <form onSubmit={apply} className="panel p-3 mb-3 grid gap-3 sm:grid-cols-2 lg:grid-cols-3" data-testid="audit-server-filters">
    {(Object.keys(empty) as (keyof typeof empty)[]).map(key => <label key={key} className="min-w-0">
      <span className="label">{t(`audit.filter.${key}`)}</span>
      <input className="field w-full" type={key === 'from' || key === 'to' ? 'datetime-local' : 'text'}
        maxLength={256} value={draft[key]} data-testid={`audit-filter-${key}`}
        onChange={e => setDraft({ ...draft, [key]: e.target.value })} />
    </label>)}
    <div className="flex flex-wrap items-center gap-2 sm:col-span-2 lg:col-span-3">
      <button type="submit" className="btn-primary" data-testid="audit-apply-filters">{t('audit.applyFilters')}</button>
      <button type="button" className="btn" data-testid="audit-clear-server-filters" onClick={() => {
        setDraft(empty); setInvalid(false); onApply({ limit: 200 });
      }}>{t('audit.clearFilters')}</button>
      <span className="text-xs text-muted">{t('audit.filterNote')}</span>
      {invalid && <span role="alert" className="text-xs text-block">{t('audit.invalidRange')}</span>}
    </div>
  </form>;
}
