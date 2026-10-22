import React, { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Pencil, Plus, Trash2 } from 'lucide-react';
import { ApiError, RuleSet, RuleSetFilter, apiClient } from '../../api/client';
import { filterSummary, setTitle } from '../../lib/ruleSets';

// RS-3c: rule sets made by operators, on Rules & packs. A policy copies a
// set's filter when saved: editing or deleting a set here changes no
// policy until the policy is saved, reviewed and deployed again.

const words = (text: string) => [...new Set(text.split(/[\s,;]+/).map((w) => w.trim()).filter(Boolean))];
const ids = (text: string) => words(text).map(Number);
const validIds = (text: string) => ids(text).every((n) => Number.isInteger(n) && n >= 1 && n <= 0xffffffff);
const suffixOk = (s: string) => /^[a-z0-9][a-z0-9-]{0,47}$/.test(s);

interface Draft { suffix: string; title: string; description: string; sources: string; attackTypes: string; tags: string; ids: string }
const empty: Draft = { suffix: '', title: '', description: '', sources: '', attackTypes: '', tags: '', ids: '' };
const draftOf = (s: RuleSet): Draft => ({
  suffix: s.name.replace(/^custom-/, ''), title: s.title.en ?? '', description: s.description ?? '',
  sources: (s.match.sources ?? []).join(', '), attackTypes: (s.match.attack_types ?? []).join(', '),
  tags: (s.match.tags ?? []).join(', '), ids: (s.match.ids ?? []).join(', '),
});
const filterOf = (d: Draft): RuleSetFilter => {
  const f: RuleSetFilter = {};
  if (words(d.sources).length) f.sources = words(d.sources);
  if (words(d.attackTypes).length) f.attack_types = words(d.attackTypes);
  if (words(d.tags).length) f.tags = words(d.tags);
  if (words(d.ids).length) f.ids = ids(d.ids);
  return f;
};

export const CustomRuleSets: React.FC<{
  sets: RuleSet[];
  facets?: { sources: string[]; attack_types: string[] };
  canWrite: boolean;
  onChanged: () => void;
}> = ({ sets, facets, canWrite, onChanged }) => {
  const { t, i18n } = useTranslation();
  const custom = sets.filter((s) => s.custom);
  const builtIn = sets.filter((s) => !s.custom);
  // undefined: no form; '': a new set; a name: that set
  const [editing, setEditing] = useState<string>();
  const [draft, setDraft] = useState<Draft>(empty);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string>();
  const current = custom.find((s) => s.name === editing);
  const filter = filterOf(draft);
  const valid = (editing !== '' || suffixOk(draft.suffix)) && draft.title.trim() !== '' && draft.title.length <= 128 &&
    draft.description.length <= 1024 && validIds(draft.ids) && Object.keys(filter).length > 0;

  const open = (s?: RuleSet) => { setEditing(s ? s.name : ''); setDraft(s ? draftOf(s) : empty); setError(undefined); };
  const fail = (e: unknown) => setError(e instanceof ApiError && e.code === 409 ? t('customSets.conflict') : t('customSets.error', { error: e instanceof Error ? e.message : String(e) }));
  const save = async () => {
    setSaving(true); setError(undefined);
    try {
      const input = { title: draft.title.trim(), description: draft.description, match: filter };
      if (current) await apiClient.updateCustomRuleSet(current.name, { ...input, etag: current.etag });
      else await apiClient.createCustomRuleSet({ ...input, name: `custom-${draft.suffix}` });
      setEditing(undefined);
      onChanged();
    } catch (e) {
      fail(e);
    } finally {
      setSaving(false);
    }
  };
  const remove = async (s: RuleSet) => {
    if (!window.confirm(t('customSets.confirmDelete', { name: s.name }))) return;
    setError(undefined);
    try {
      await apiClient.deleteCustomRuleSet(s.name, s.etag ?? '');
      onChanged();
    } catch (e) {
      fail(e);
    }
  };
  const field = (key: keyof Draft, label: string, list?: string[]) => (
    <label className="block min-w-0 text-sm">{label}
      <input className="field mt-1 block w-full" value={draft[key]} list={list ? `custom-${key}` : undefined}
        onChange={(e) => setDraft({ ...draft, [key]: e.target.value })} data-testid={`custom-${key}`} />
      {list && <datalist id={`custom-${key}`}>{list.map((v) => <option key={v} value={v} />)}</datalist>}
    </label>
  );

  return (
    <section className="panel relative p-3 mb-3 overflow-x-auto" data-testid="custom-sets">
      <div className="flex flex-wrap items-center gap-2 mb-2">
        <h2 className="font-medium">{t('customSets.title')}</h2>
        {canWrite && editing === undefined && <button type="button" className="btn ml-auto" onClick={() => open()} data-testid="custom-new"><Plus className="w-3.5 h-3.5" />{t('customSets.new')}</button>}
      </div>
      <p className="text-sm text-muted mb-2">{t('customSets.help')}</p>
      {error && <p role="alert" className="text-sm text-block mb-2">{error}</p>}
      {editing !== undefined && (
        <form className="rounded-md border border-line p-3 mb-3 space-y-3" onSubmit={(e) => { e.preventDefault(); if (valid && !saving) void save(); }} data-testid="custom-form">
          {editing === '' && (
            <div className="grid gap-3 sm:grid-cols-2">
              <label className="block min-w-0 text-sm">{t('customSets.name')}
                <span className="mt-1 flex items-center gap-1"><span className="font-mono text-xs text-muted">custom-</span>
                  <input className="field min-w-0 flex-1 font-mono" value={draft.suffix} maxLength={48} aria-invalid={draft.suffix !== '' && !suffixOk(draft.suffix)}
                    onChange={(e) => setDraft({ ...draft, suffix: e.target.value.toLowerCase() })} data-testid="custom-suffix" /></span>
              </label>
              <label className="block min-w-0 text-sm">{t('customSets.copyFrom')}
                <select className="field mt-1 block w-full" value="" onChange={(e) => {
                  const s = builtIn.find((x) => x.name === e.target.value);
                  if (s) setDraft({ ...draftOf(s), suffix: draft.suffix || s.name, title: setTitle(s, i18n.language) });
                }} data-testid="custom-copy">
                  <option value="">{t('customSets.copyNone')}</option>
                  {builtIn.map((s) => <option key={s.name} value={s.name}>{setTitle(s, i18n.language)}</option>)}
                </select>
              </label>
            </div>
          )}
          {editing !== '' && <p className="font-mono text-sm">{editing}</p>}
          <div className="grid gap-3 sm:grid-cols-2">
            {field('title', t('customSets.setTitle'))}
            {field('description', t('customSets.description'))}
            {field('sources', t('customSets.sources'), facets?.sources)}
            {field('attackTypes', t('customSets.attackTypes'), facets?.attack_types)}
            {field('tags', t('customSets.tags'))}
            {field('ids', t('customSets.ids'))}
          </div>
          <p className="text-xs text-muted">{t('customSets.filterHelp')}</p>
          {!validIds(draft.ids) && <p className="text-xs text-block">{t('customSets.badIds')}</p>}
          {current && <p className="text-xs text-muted">{t('customSets.editNote')}</p>}
          <div className="flex gap-2">
            <button type="submit" className="btn-primary" disabled={!valid || saving} data-testid="custom-save">{t(saving ? 'customSets.saving' : 'customSets.save')}</button>
            <button type="button" className="btn" disabled={saving} onClick={() => setEditing(undefined)}>{t('customSets.cancel')}</button>
          </div>
        </form>
      )}
      {custom.length === 0 ? <p className="text-sm text-muted" data-testid="custom-empty">{t('customSets.none')}</p> : (
        <table className="w-full text-sm">
          <thead><tr>{['name', 'filter', 'rules', 'version'].map((k) => <th key={k} className="p-2 text-left">{t(`customSets.col.${k}`)}</th>)}{canWrite && <th className="p-2"><span className="sr-only">{t('customSets.actions')}</span></th>}</tr></thead>
          <tbody>
            {custom.map((s) => (
              <tr key={s.name} className="border-t border-line" data-testid="custom-row">
                <td className="p-2"><span className="font-mono text-xs">{s.name}</span><p>{s.title.en}</p>{s.description && <p className="text-xs text-muted">{s.description}</p>}</td>
                <td className="p-2 font-mono text-xs break-all">{filterSummary(s.match)}</td>
                <td className="p-2">{s.rule_count ?? '—'}</td>
                <td className="p-2 whitespace-nowrap">v{s.version}{s.updated_by && <span className="text-muted"> · {s.updated_by}</span>}</td>
                {canWrite && <td className="p-2 whitespace-nowrap">
                  <button type="button" className="btn" aria-label={t('customSets.edit', { name: s.name })} onClick={() => open(s)} data-testid={`custom-edit-${s.name}`}><Pencil className="w-3.5 h-3.5" /></button>
                  <button type="button" className="btn ml-1" aria-label={t('customSets.delete', { name: s.name })} onClick={() => void remove(s)} data-testid={`custom-delete-${s.name}`}><Trash2 className="w-3.5 h-3.5" /></button>
                </td>}
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
};
