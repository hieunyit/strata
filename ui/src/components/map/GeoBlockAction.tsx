import React, { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { ShieldBan } from 'lucide-react';
import { apiClient, ApiError, Policy } from '../../api/client';
import { withGeoRule } from '../../lib/geoRules';
import { href } from '../../router';

// "Create a geo/ASN block rule" from the map (W19-F-01): adds a geo rule
// for the country or ASN picked to a policy, as a new draft version. It is
// enforced only after replay, approval and deploy, like any policy change.
export const GeoBlockAction: React.FC<{ country?: string; asn?: number; label: string; policies: Policy[]; defaultPolicy?: string }> = ({
  country,
  asn,
  label,
  policies,
  defaultPolicy,
}) => {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const [policyId, setPolicyId] = useState(defaultPolicy ?? policies[0]?.id ?? '');
  const [action, setAction] = useState<'ACTION_BLOCK' | 'ACTION_LOG'>('ACTION_BLOCK');
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<{ ok: boolean; text: string } | undefined>();

  const create = async () => {
    setBusy(true);
    setResult(undefined);
    try {
      // the policy as it is now: its spec and etag
      const fresh = (await apiClient.listPolicies()).find((p) => p.id === policyId);
      if (!fresh) throw new Error(t('map.geoAction.noPolicy'));
      const { spec, added } = withGeoRule(fresh.spec ?? {}, country ? { country } : { asn }, action);
      if (!added) {
        setResult({ ok: true, text: t('map.geoAction.exists', { target: label, policy: fresh.name }) });
        return;
      }
      const saved = await apiClient.updatePolicy(fresh.id ?? '', spec, fresh.etag ?? '');
      setResult({ ok: true, text: t('map.geoAction.saved', { target: label, policy: fresh.name, version: saved.version ?? '' }) });
    } catch (e) {
      const msg = e instanceof ApiError && e.code === 409 ? t('editor.conflict') : e instanceof Error ? e.message : String(e);
      setResult({ ok: false, text: t('map.geoAction.failed', { error: msg }) });
    } finally {
      setBusy(false);
    }
  };

  if (!open) {
    return (
      <button type="button" className="btn" onClick={() => setOpen(true)} data-testid="map-geo-action">
        <ShieldBan className="h-4 w-4" /> {t('map.geoAction.open', { target: label })}
      </button>
    );
  }
  return (
    <div className="panel flex flex-wrap items-center gap-2 px-3 py-2 text-[13px]" data-testid="map-geo-form">
      <span className="font-medium">{t('map.geoAction.title', { target: label })}</span>
      <select className="field w-auto" value={policyId} onChange={(e) => setPolicyId(e.target.value)} aria-label={t('map.geoAction.policy')} data-testid="map-geo-policy">
        {policies.map((p) => (
          <option key={p.id} value={p.id}>
            {p.name}
          </option>
        ))}
      </select>
      <select className="field w-auto" value={action} onChange={(e) => setAction(e.target.value as typeof action)} aria-label={t('editor.geo.action')} data-testid="map-geo-mode">
        <option value="ACTION_BLOCK">{t('editor.geo.block')}</option>
        <option value="ACTION_LOG">{t('editor.geo.log')}</option>
      </select>
      <button type="button" className="btn btn-primary" disabled={busy || !policyId} onClick={() => void create()} data-testid="map-geo-create">
        {t('map.geoAction.create')}
      </button>
      <button type="button" className="btn" onClick={() => setOpen(false)}>
        {t('editor.cancel')}
      </button>
      <p className="basis-full text-xs text-muted">{t('map.geoAction.note')}</p>
      {result && (
        <p className={`basis-full text-xs ${result.ok ? 'text-ink' : 'text-block'}`} role="status" data-testid="map-geo-result">
          {result.text}{' '}
          {result.ok && (
            <a className="text-accent hover:underline" href={href({ page: 'policies' })}>
              {t('map.geoAction.review')}
            </a>
          )}
        </p>
      )}
    </div>
  );
};
