import React, { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { apiClient, ApiError, Policy, PolicyTemplate } from '../../api/client';
import { ErrorBanner } from '../ui';

const idPattern = /^[a-z0-9][a-z0-9-]{0,62}$/;
const namePattern = /^[a-z0-9._-]{1,55}$/;

// A new policy from a template (W20-S-01): the template's settings are
// copied into its first version (a draft); the policy is on its own after.
export const NewPolicy: React.FC<{ onCreated: (p: Policy) => void; onCancel: () => void }> = ({ onCreated, onCancel }) => {
  const { t } = useTranslation();
  const [templates, setTemplates] = useState<PolicyTemplate[]>([]);
  const [template, setTemplate] = useState('api');
  const [id, setId] = useState('');
  const [name, setName] = useState('');
  const [error, setError] = useState<string | undefined>();
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    apiClient
      .listPolicyTemplates()
      .then((ts) => {
        setTemplates(ts);
        if (ts.length && !ts.some((x) => x.name === 'api')) setTemplate(ts[0].name ?? '');
      })
      .catch((e) => setError(e instanceof Error ? e.message : String(e)));
  }, []);

  const chosen = templates.find((x) => x.name === template);
  const valid = idPattern.test(id) && namePattern.test(name) && !/^\.+$/.test(name);

  const create = async () => {
    setBusy(true);
    setError(undefined);
    try {
      onCreated(await apiClient.createPolicy(id, name, template));
    } catch (e) {
      setError(e instanceof ApiError && e.code === 409 ? t('policies.new.exists') : e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="panel mb-5 space-y-3 p-4 text-[13px]" data-testid="new-policy">
      <h2 className="text-sm font-semibold">{t('policies.new.title')}</h2>
      <ErrorBanner message={error} />
      <div className="grid gap-3 sm:grid-cols-3">
        <label className="space-y-1">
          <span className="label">{t('policies.new.id')}</span>
          <input className="field" value={id} onChange={(e) => setId(e.target.value)} placeholder="example-api" data-testid="new-policy-id" />
        </label>
        <label className="space-y-1">
          <span className="label">{t('policies.new.name')}</span>
          <input className="field" value={name} onChange={(e) => setName(e.target.value)} placeholder="example-api" data-testid="new-policy-name" />
        </label>
        <label className="space-y-1">
          <span className="label">{t('policies.new.template')}</span>
          <select className="field" value={template} onChange={(e) => setTemplate(e.target.value)} data-testid="new-policy-template">
            {templates.map((x) => (
              <option key={x.name} value={x.name}>
                {x.name} (v{x.version})
              </option>
            ))}
          </select>
        </label>
      </div>
      {chosen && (
        <p className="text-xs text-muted" data-testid="new-policy-description">
          {chosen.description}
        </p>
      )}
      <p className="text-xs text-muted">{t('policies.new.note')}</p>
      <div className="flex gap-2">
        <button type="button" className="btn btn-primary" disabled={!valid || busy || !template} onClick={() => void create()} data-testid="new-policy-create">
          {t('policies.new.create')}
        </button>
        <button type="button" className="btn" onClick={onCancel}>
          {t('editor.cancel')}
        </button>
      </div>
    </section>
  );
};
