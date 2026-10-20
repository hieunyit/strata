import React, { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Plus, Trash2 } from 'lucide-react';
import { GeoRule, MAX_GEO_RULES, parseAsns, parseCountries } from '../../lib/geoRules';

// The geo rules of a policy (W19-F-01): countries and ASNs typed as lists,
// block or log, optionally the addresses outside them. New rules have no
// id until saved: the control plane assigns it.
export const GeoRulesEditor: React.FC<{ rules: GeoRule[]; onChange: (rules: GeoRule[]) => void }> = ({ rules, onChange }) => {
  const { t } = useTranslation();
  // the text typed, per row, so a half-typed list stays as typed
  const [texts, setTexts] = useState<{ countries: string; asns: string }[]>(() =>
    rules.map((r) => ({ countries: (r.countries ?? []).join(', '), asns: (r.asns ?? []).join(', ') })),
  );
  const set = (i: number, patch: Partial<GeoRule>) => onChange(rules.map((r, k) => (k === i ? { ...r, ...patch } : r)));
  const setText = (i: number, key: 'countries' | 'asns', value: string) => {
    setTexts(texts.map((x, k) => (k === i ? { ...x, [key]: value } : x)));
    set(i, key === 'countries' ? { countries: parseCountries(value).values } : { asns: parseAsns(value).values });
  };
  return (
    <fieldset className="space-y-2 text-[13px]" data-testid="editor-geo-rules">
      <legend className="label">{t('editor.geo.title')}</legend>
      {rules.map((r, i) => {
        const bad = [...parseCountries(texts[i]?.countries ?? '').bad, ...parseAsns(texts[i]?.asns ?? '').bad];
        const empty = !(r.countries?.length || r.asns?.length);
        return (
          <div key={i} className="rounded-md border border-line p-2 space-y-1.5" data-testid="editor-geo-rule">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-xs text-muted">{r.id ? `#${r.id}` : t('editor.geo.new')}</span>
              <select
                className="field w-auto"
                value={r.action === 'ACTION_LOG' ? 'ACTION_LOG' : 'ACTION_BLOCK'}
                onChange={(e) => set(i, { action: e.target.value as GeoRule['action'] })}
                aria-label={t('editor.geo.action')}
                data-testid="editor-geo-action"
              >
                <option value="ACTION_BLOCK">{t('editor.geo.block')}</option>
                <option value="ACTION_LOG">{t('editor.geo.log')}</option>
              </select>
              <label className="flex items-center gap-1.5">
                <input type="checkbox" checked={!!r.not} onChange={(e) => set(i, { not: e.target.checked })} data-testid="editor-geo-not" />
                {t('editor.geo.not')}
              </label>
              <button
                type="button"
                className="ml-auto text-muted hover:text-block"
                aria-label={t('editor.geo.remove')}
                onClick={() => {
                  setTexts(texts.filter((_, k) => k !== i));
                  onChange(rules.filter((_, k) => k !== i));
                }}
                data-testid="editor-geo-remove"
              >
                <Trash2 className="h-4 w-4" />
              </button>
            </div>
            <div className="grid gap-2 sm:grid-cols-2">
              <input
                className="field"
                placeholder={t('editor.geo.countries')}
                aria-label={t('editor.geo.countries')}
                value={texts[i]?.countries ?? ''}
                onChange={(e) => setText(i, 'countries', e.target.value)}
                data-testid="editor-geo-countries"
              />
              <input
                className="field"
                placeholder={t('editor.geo.asns')}
                aria-label={t('editor.geo.asns')}
                value={texts[i]?.asns ?? ''}
                onChange={(e) => setText(i, 'asns', e.target.value)}
                data-testid="editor-geo-asns"
              />
            </div>
            {(bad.length > 0 || empty) && (
              <p className="text-xs text-block" role="alert" data-testid="editor-geo-error">
                {bad.length > 0 ? t('editor.geo.bad', { list: bad.join(', ') }) : t('editor.geo.empty')}
              </p>
            )}
          </div>
        );
      })}
      {rules.length < MAX_GEO_RULES && (
        <button
          type="button"
          className="btn"
          onClick={() => {
            setTexts([...texts, { countries: '', asns: '' }]);
            onChange([...rules, { action: 'ACTION_BLOCK' }]);
          }}
          data-testid="editor-geo-add"
        >
          <Plus className="h-4 w-4" /> {t('editor.geo.add')}
        </button>
      )}
      <p className="text-xs text-muted">{t('editor.geo.note')}</p>
    </fieldset>
  );
};
