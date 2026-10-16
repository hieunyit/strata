import React, { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Save, X, Layers, Sliders, Shield, FileText, CheckCircle2, AlertTriangle, Code, ShieldAlert, Ban } from 'lucide-react';
import { ApiError, Policy, apiClient } from '../../api/client';
import { DATA_GUARDS, PolicySpec, YamlError, normalizeSpec, specToYaml, validCanary, yamlToSpec } from '../../lib/policyYaml';
import { ErrorBanner, SectionTitle } from '../ui';

export type PolicyBlockId =
  | 'all'
  | 'general'
  | 'template'
  | 'entities'
  | 'violations'
  | 'signatures'
  | 'custom_rules'
  | 'overrides'
  | 'exceptions'
  | 'response';

interface BlockDefinition {
  id: PolicyBlockId;
  label: string;
  shortLabel: string;
  icon: React.ComponentType<{ className?: string }>;
}

const BLOCKS: BlockDefinition[] = [
  { id: 'all', label: 'All 9 Blocks', shortLabel: 'All', icon: Layers },
  { id: 'general', label: '1. General', shortLabel: 'General', icon: Sliders },
  { id: 'template', label: '2. Template', shortLabel: 'Template', icon: FileText },
  { id: 'entities', label: '3. Entities & Profiles', shortLabel: 'Entities', icon: Code },
  { id: 'violations', label: '4. Violations', shortLabel: 'Violations', icon: AlertTriangle },
  { id: 'signatures', label: '5. Signatures', shortLabel: 'Signatures', icon: Shield },
  { id: 'custom_rules', label: '6. Custom Rules', shortLabel: 'Custom', icon: CheckCircle2 },
  { id: 'overrides', label: '7. Overrides', shortLabel: 'Overrides', icon: ShieldAlert },
  { id: 'exceptions', label: '8. Exceptions', shortLabel: 'Exceptions', icon: Ban },
  { id: 'response', label: '9. Response', shortLabel: 'Response', icon: Layers },
];

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
  const [activeBlock, setActiveBlock] = useState<PolicyBlockId>('all');

  // Extended UI draft settings for 9-block simulation & configuration
  const [template, setTemplate] = useState('base');
  const [contentProfiles, setContentProfiles] = useState<string[]>(['json', 'form']);
  const [violations, setViolations] = useState<Record<string, { alarm: boolean; block: boolean }>>({
    PROTO_CL_TE_CONFLICT: { alarm: true, block: true },
    EVASION_DOUBLE_ENCODING: { alarm: true, block: true },
    SCHEMA_UNKNOWN_FIELD: { alarm: true, block: false },
    DATA_LEAK_CCCD: { alarm: true, block: true },
  });
  const [signatures, setSignatures] = useState<string[]>(['owasp-crs-pl1', 'sqli', 'xss', 'cmdi']);
  const [maxArgs, setMaxArgs] = useState<number>(spec.max_args ?? 1024);
  const [maxSnippet, setMaxSnippet] = useState<number>(spec.max_snippet_size ?? 128);

  const dirty = JSON.stringify(spec) !== JSON.stringify(initial);

  const update = (next: PolicySpec) => {
    const n = normalizeSpec(next);
    setSpec(n);
    setYaml(specToYaml(n));
    setYamlError(undefined);
  };

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

  const showBlock = (b: PolicyBlockId) => activeBlock === 'all' || activeBlock === b;

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

        {/* 9 Blocks Tab Selector Bar */}
        <div className="flex flex-wrap gap-1 border-b border-line pb-2 mb-4">
          {BLOCKS.map((b) => {
            const Icon = b.icon;
            const active = activeBlock === b.id;
            return (
              <button
                key={b.id}
                type="button"
                data-testid={`block-tab-${b.id}`}
                onClick={() => setActiveBlock(b.id)}
                className={`inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium rounded transition-colors ${
                  active
                    ? 'bg-ink text-paper'
                    : 'bg-sunken text-muted hover:text-ink hover:bg-line/40'
                }`}
              >
                <Icon className="w-3 h-3" />
                <span>{b.label}</span>
              </button>
            );
          })}
        </div>
      </div>

      <div className="grid gap-4 px-4 pb-4 lg:grid-cols-2">
        <form className="space-y-6" onSubmit={(e) => e.preventDefault()} data-testid="editor-form">
          {/* Block 1: General Settings */}
          {showBlock('general') && (
            <div className="p-3 bg-sunken/40 rounded border border-line/60 space-y-3" data-testid="block-general">
              <div className="flex items-center justify-between border-b border-line/40 pb-1.5">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-muted flex items-center gap-1.5">
                  <Sliders className="w-3.5 h-3.5 text-accent" />
                  1. General Settings
                </h3>
              </div>
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
              <div className="grid grid-cols-2 gap-3 text-xs">
                <div>
                  <label className="label" htmlFor="editor-max-args">Max Inspected Args</label>
                  <input
                    id="editor-max-args"
                    type="number"
                    className="field"
                    value={maxArgs}
                    onChange={(e) => setMaxArgs(Number(e.target.value))}
                    data-testid="editor-max-args"
                  />
                  <p className="mt-0.5 text-[11px] text-muted">Rule 100021 guard limit (1–1024)</p>
                </div>
                <div>
                  <label className="label" htmlFor="editor-max-snippet">Event Snippet Size</label>
                  <select
                    id="editor-max-snippet"
                    className="field"
                    value={maxSnippet}
                    onChange={(e) => setMaxSnippet(Number(e.target.value))}
                    data-testid="editor-max-snippet"
                  >
                    <option value={128}>128 bytes (Default)</option>
                    <option value={2048}>2048 bytes (Diagnostic)</option>
                    <option value={4096}>4096 bytes (Deep)</option>
                  </select>
                </div>
              </div>
            </div>
          )}

          {/* Block 2: Template Inheritance */}
          {showBlock('template') && (
            <div className="p-3 bg-sunken/40 rounded border border-line/60 space-y-3" data-testid="block-template">
              <div className="flex items-center justify-between border-b border-line/40 pb-1.5">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-muted flex items-center gap-1.5">
                  <FileText className="w-3.5 h-3.5 text-accent" />
                  2. Template Inheritance
                </h3>
              </div>
              <div>
                <label className="label" htmlFor="editor-template-select">Base Template</label>
                <select
                  id="editor-template-select"
                  className="field"
                  value={template}
                  onChange={(e) => setTemplate(e.target.value)}
                  data-testid="editor-template"
                >
                  <option value="base">base — Standard OWASP CRS Core</option>
                  <option value="strict">strict — High-Security Banking & FinTech</option>
                  <option value="api">api — Strict OpenAPI & JSON IDL</option>
                  <option value="wordpress">wordpress — CMS Exclusions Pre-tuned</option>
                  <option value="php-legacy">php-legacy — Hardened for Legacy Stacks</option>
                </select>
                <p className="mt-1 text-xs text-muted">Policies inherit defaults and only store explicit diffs.</p>
              </div>
            </div>
          )}

          {/* Block 3: Entities & Profiles */}
          {showBlock('entities') && (
            <div className="p-3 bg-sunken/40 rounded border border-line/60 space-y-3" data-testid="block-entities">
              <div className="flex items-center justify-between border-b border-line/40 pb-1.5">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-muted flex items-center gap-1.5">
                  <Code className="w-3.5 h-3.5 text-accent" />
                  3. Entities & Content Profiles
                </h3>
              </div>
              <fieldset className="space-y-1.5 text-[13px]">
                <legend className="label">Active Payload Parsers</legend>
                {[
                  { id: 'json', label: 'JSON Fast-Path Parser' },
                  { id: 'xml', label: 'XML & DTD Inspector' },
                  { id: 'graphql', label: 'GraphQL Depth & Query Inspector' },
                  { id: 'form', label: 'Form URL-encoded & Multipart' },
                ].map((p) => (
                  <label key={p.id} className="flex items-center gap-1.5">
                    <input
                      type="checkbox"
                      checked={contentProfiles.includes(p.id)}
                      onChange={(e) =>
                        setContentProfiles(
                          e.target.checked ? [...contentProfiles, p.id] : contentProfiles.filter((x) => x !== p.id)
                        )
                      }
                      data-testid={`editor-profile-${p.id}`}
                    />
                    {p.label}
                  </label>
                ))}
              </fieldset>
            </div>
          )}

          {/* Block 4: Violations Catalog */}
          {showBlock('violations') && (
            <div className="p-3 bg-sunken/40 rounded border border-line/60 space-y-3" data-testid="block-violations">
              <div className="flex items-center justify-between border-b border-line/40 pb-1.5">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-muted flex items-center gap-1.5">
                  <AlertTriangle className="w-3.5 h-3.5 text-accent" />
                  4. Violations Catalog
                </h3>
              </div>
              <div className="space-y-2 text-xs">
                {Object.entries(violations).map(([k, v]) => (
                  <div key={k} className="flex items-center justify-between p-1.5 bg-paper rounded border border-line/40">
                    <span className="font-mono text-[11px] text-ink">{k}</span>
                    <div className="flex items-center gap-3">
                      <label className="flex items-center gap-1 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={v.alarm}
                          onChange={(e) =>
                            setViolations({ ...violations, [k]: { ...v, alarm: e.target.checked } })
                          }
                        />
                        Alarm
                      </label>
                      <label className="flex items-center gap-1 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={v.block}
                          onChange={(e) =>
                            setViolations({ ...violations, [k]: { ...v, block: e.target.checked } })
                          }
                        />
                        Block
                      </label>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Block 5: Signature Sets */}
          {showBlock('signatures') && (
            <div className="p-3 bg-sunken/40 rounded border border-line/60 space-y-3" data-testid="block-signatures">
              <div className="flex items-center justify-between border-b border-line/40 pb-1.5">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-muted flex items-center gap-1.5">
                  <Shield className="w-3.5 h-3.5 text-accent" />
                  5. Signature Sets
                </h3>
              </div>
              <fieldset className="space-y-1.5 text-[13px]">
                {[
                  { id: 'owasp-crs-pl1', label: 'OWASP Core Rule Set (PL1)' },
                  { id: 'sqli', label: 'SQL Injection Signatures & libinjection' },
                  { id: 'xss', label: 'Cross-Site Scripting (XSS) Patterns' },
                  { id: 'cmdi', label: 'Command Injection (CMDi) Semantic Guard' },
                  { id: 'threat-campaigns', label: 'Active Threat Campaigns (Virtual Patches)' },
                ].map((s) => (
                  <label key={s.id} className="flex items-center gap-1.5">
                    <input
                      type="checkbox"
                      checked={signatures.includes(s.id)}
                      onChange={(e) =>
                        setSignatures(
                          e.target.checked ? [...signatures, s.id] : signatures.filter((x) => x !== s.id)
                        )
                      }
                      data-testid={`editor-sig-${s.id}`}
                    />
                    {s.label}
                  </label>
                ))}
              </fieldset>
            </div>
          )}

          {/* Block 6: Custom Rules */}
          {showBlock('custom_rules') && (
            <div className="p-3 bg-sunken/40 rounded border border-line/60 space-y-3" data-testid="block-custom-rules">
              <div className="flex items-center justify-between border-b border-line/40 pb-1.5">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-muted flex items-center gap-1.5">
                  <CheckCircle2 className="w-3.5 h-3.5 text-accent" />
                  6. Custom Rules
                </h3>
              </div>
              <p className="text-xs text-muted">
                Phase-based rules evaluated across: <code>pre</code>, <code>protocol</code>, <code>rate</code>, <code>managed</code>, <code>custom-post</code>.
              </p>
              <div className="p-2 bg-paper rounded border border-line/40 font-mono text-xs text-muted">
                # No custom rule overrides active in draft.
              </div>
            </div>
          )}

          {/* Block 7: Overrides */}
          {showBlock('overrides') && (
            <div className="p-3 bg-sunken/40 rounded border border-line/60 space-y-3" data-testid="block-overrides">
              <div className="flex items-center justify-between border-b border-line/40 pb-1.5">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-muted flex items-center gap-1.5">
                  <ShieldAlert className="w-3.5 h-3.5 text-accent" />
                  7. Overrides
                </h3>
              </div>
              <p className="text-xs text-muted">
                Condition-based configuration changes (e.g., disable signature X for <code>/upload</code> when <code>Content-Type</code> is multipart).
              </p>
              <div className="p-2 bg-paper rounded border border-line/40 font-mono text-xs text-muted">
                # No path overrides configured.
              </div>
            </div>
          )}

          {/* Block 8: Exceptions */}
          {showBlock('exceptions') && (
            <div className="p-3 bg-sunken/40 rounded border border-line/60 space-y-3" data-testid="block-exceptions">
              <div className="flex items-center justify-between border-b border-line/40 pb-1.5">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-muted flex items-center gap-1.5">
                  <Ban className="w-3.5 h-3.5 text-accent" />
                  8. Exceptions (Narrow Scope & TTL)
                </h3>
              </div>
              <p className="text-xs text-muted">
                Narrow-scope rule exceptions generated from Block IDs (route + field + Rule ID). Higher evaluation priority than overrides.
              </p>
              <div className="p-2 bg-paper rounded border border-line/40 font-mono text-xs text-muted">
                # Exceptions active: 0. Generated automatically via Block ID inspection.
              </div>
            </div>
          )}

          {/* Block 9: Response Layer */}
          {showBlock('response') && (
            <div className="p-3 bg-sunken/40 rounded border border-line/60 space-y-3" data-testid="block-response">
              <div className="flex items-center justify-between border-b border-line/40 pb-1.5">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-muted flex items-center gap-1.5">
                  <Layers className="w-3.5 h-3.5 text-accent" />
                  9. Response Layer
                </h3>
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
            </div>
          )}
        </form>

        {/* Right Pane: Live YAML Editor & Validator */}
        <div>
          <label className="label" htmlFor="editor-yaml">{t('editor.yaml')}</label>
          <textarea
            id="editor-yaml"
            className="field h-96 font-mono text-xs leading-5 py-2"
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
