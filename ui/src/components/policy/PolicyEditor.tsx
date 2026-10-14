import React, { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Save, X } from 'lucide-react';
import { ApiError, Policy, apiClient } from '../../api/client';
import { DATA_GUARDS, PolicySpec, YamlError, normalizeSpec, specToYaml, validCanary, yamlToSpec } from '../../lib/policyYaml';
import { ErrorBanner, SectionTitle } from '../ui';

// Policy editor, part 1 (W11-F-01): a form and its YAML side by side, kept
// in sync both ways. Saving makes a new version of the policy in state
// DRAFT (PATCH with the etag it was read with); deploying it is a separate
// step. Diff, replay and approval come with W12-F-01 and W13.
export const PolicyEditor: React.FC<{
  policy: Policy;
  onSaved: (p: Policy) => void;
  onCancel: () => void;
}> = ({ policy, onSaved, onCancel }) => {
  const { t } = useTranslation();
  const initial = useMemo(() => normalizeSpec(policy.spec ?? {}), [policy]);
  const [spec, setSpec] = useState<PolicySpec>(initial);
  const [yaml, setYaml] = useState(() => specToYaml(initial));
  const [yamlError, setYamlError] = useState<YamlError | undefined>();
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | undefined>();

  const dirty = JSON.stringify(spec) !== JSON.stringify(initial);

  // a form edit rewrites the YAML from the spec
  const update = (next: PolicySpec) => {
    const n = normalizeSpec(next);
    setSpec(n);
    setYaml(specToYaml(n));
    setYamlError(undefined);
  };

  // a YAML edit updates the form once it reads; until then the form keeps
  // the last valid spec and saving is off
  const editYaml = (text: string) => {
    setYaml(text);
    const r = yamlToSpec(text);
    if (r.error) {
      setYamlError(r.error);
    } else {
      setYamlError(undefined);
      setSpec(normalizeSpec(r.spec));
    }
  };

  const guards = spec.response?.data_guard ?? [];
  const setResponse = (patch: Partial<NonNullable<PolicySpec['response']>>) =>
    update({ ...spec, response: { ...spec.response, ...patch } });
  const toggleGuard = (g: string) =>
    setResponse({ data_guard: guards.includes(g) ? guards.filter((x) => x !== g) : [...guards, g] });

  const save = async () => {
    setSaving(true);
    setSaveError(undefined);
    try {
      onSaved(await apiClient.updatePolicy(policy.id ?? '', spec, policy.etag ?? ''));
    } catch (e) {
      if (e instanceof ApiError && e.code === 409) setSaveError(t('editor.conflict'));
      else setSaveError(t('editor.saveError', { error: e instanceof Error ? e.message : String(e) }));
    } finally {
      setSaving(false);
    }
  };

  return (
    <section className="panel" data-testid="policy-editor">
      <SectionTitle
        aside={
          <span className="flex gap-2">
            <button type="button" className="btn" onClick={onCancel} data-testid="editor-cancel">
              <X className="w-3.5 h-3.5" />
              {t('editor.cancel')}
            </button>
            <button
              type="button"
              className="btn-primary"
              onClick={() => void save()}
              disabled={!dirty || !!yamlError || saving}
              data-testid="editor-save"
            >
              <Save className="w-3.5 h-3.5" />
              {saving ? t('editor.saving') : t('editor.saveDraft')}
            </button>
          </span>
        }
      >
        {t('editor.title', { name: policy.name, version: policy.version })}
      </SectionTitle>
      <div className="px-4 pt-3">
        <ErrorBanner message={saveError} testId="editor-save-error" />
        <p className="text-xs text-muted mb-3">{t('editor.draftNote')}</p>
      </div>
      <div className="grid gap-4 px-4 pb-4 lg:grid-cols-2">
        <form className="space-y-4" onSubmit={(e) => e.preventDefault()} data-testid="editor-form">
          <fieldset>
            <legend className="label">{t('editor.mode')}</legend>
            <div className="flex gap-4 text-[13px]">
              {(['MODE_SHADOW', 'MODE_ENFORCE'] as const).map((m) => (
                <label key={m} className="flex items-center gap-1.5">
                  <input
                    type="radio"
                    name="mode"
                    value={m}
                    checked={spec.mode === m}
                    onChange={() => update({ ...spec, mode: m })}
                    data-testid={`editor-mode-${m}`}
                  />
                  {t(`policies.mode.${m}`)}
                </label>
              ))}
            </div>
          </fieldset>
          {spec.mode === 'MODE_ENFORCE' && (
            <div>
              <label className="label" htmlFor="editor-canary">{t('editor.canary')}</label>
              <input
                id="editor-canary"
                type="number"
                className="field w-32"
                min={0.01}
                max={99.99}
                step={0.01}
                placeholder="100"
                value={spec.canary_percent ?? ''}
                onChange={(e) => {
                  const n = e.target.value === '' ? undefined : Number(e.target.value);
                  update({ ...spec, canary_percent: validCanary(n) ? n : undefined });
                }}
                data-testid="editor-canary"
              />
              <p className="mt-1 text-xs text-muted">{t('editor.canaryNote')}</p>
            </div>
          )}
          <div>
            <label className="label" htmlFor="editor-oversize">{t('editor.oversize')}</label>
            <select
              id="editor-oversize"
              className="field"
              value={spec.oversize ?? 'OVERSIZE_UNSPECIFIED'}
              onChange={(e) => update({ ...spec, oversize: e.target.value as PolicySpec['oversize'] })}
              data-testid="editor-oversize"
            >
              <option value="OVERSIZE_UNSPECIFIED">{t('policies.oversize.OVERSIZE_UNSPECIFIED')}</option>
              <option value="OVERSIZE_BLOCK">{t('policies.oversize.OVERSIZE_BLOCK')}</option>
            </select>
          </div>
          <fieldset className="space-y-1.5 text-[13px]">
            <legend className="label">{t('editor.response')}</legend>
            <label className="flex items-center gap-1.5">
              <input
                type="checkbox"
                checked={!!spec.response?.allowed_codes_check}
                onChange={(e) => setResponse({ allowed_codes_check: e.target.checked })}
                data-testid="editor-allowed-codes"
              />
              {t('editor.allowedCodes')}
            </label>
            <label className="flex items-center gap-1.5">
              <input
                type="checkbox"
                checked={!!spec.response?.db_errors}
                onChange={(e) => setResponse({ db_errors: e.target.checked })}
                data-testid="editor-db-errors"
              />
              {t('editor.dbErrors')}
            </label>
            {DATA_GUARDS.map((g) => (
              <label key={g} className="flex items-center gap-1.5">
                <input
                  type="checkbox"
                  checked={guards.includes(g)}
                  onChange={() => toggleGuard(g)}
                  data-testid={`editor-guard-${g}`}
                />
                {t(`editor.guard.${g}`)}
              </label>
            ))}
          </fieldset>
        </form>
        <div>
          <label className="label" htmlFor="editor-yaml">{t('editor.yaml')}</label>
          <textarea
            id="editor-yaml"
            className="field h-56 font-mono text-xs leading-5 py-2"
            spellCheck={false}
            value={yaml}
            onChange={(e) => editYaml(e.target.value)}
            aria-invalid={!!yamlError}
            data-testid="editor-yaml"
          />
          {yamlError && (
            <p className="mt-1 text-xs text-block" role="alert" data-testid="editor-yaml-error">
              {t('editor.yamlError', { line: yamlError.line, message: t(`editor.yamlErr.${yamlError.code}`, yamlError.args ?? {}) })}
            </p>
          )}
        </div>
      </div>
    </section>
  );
};
