import React, { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { apiClient, Application } from '../../api/client';

export const ApplicationScope: React.FC<{ application: string; environment: string; onChange: (application: string, environment: string) => void }> = ({ application, environment, onChange }) => {
  const { t } = useTranslation();
  const [apps, setApps] = useState<Application[]>([]), [after, setAfter] = useState(''), [error, setError] = useState(false);
  const load = async (cursor = '') => {
    try { const r = await apiClient.listApplications(cursor); setApps((old) => cursor ? [...old, ...r.applications] : r.applications); setAfter(r.next_cursor ?? ''); setError(false); }
    catch { setError(true); }
  };
  useEffect(() => { void load(); }, []);
  const selected = apps.find((v) => v.id === application);
  return <div className="flex gap-3 flex-wrap items-end">
    <label>{t('investigation.application')}<select className="field block" value={application} onChange={(e) => onChange(e.target.value, '')}><option value="">{t('investigation.select')}</option>{apps.map((v) => <option key={v.id} value={v.id}>{v.name}</option>)}</select></label>
    <label>{t('investigation.environment')}<select className="field block" value={environment} onChange={(e) => onChange(application, e.target.value)}><option value="">{t('investigation.select')}</option>{selected?.environments.map((v) => <option key={v.id} value={v.id}>{v.name}</option>)}</select></label>
    {after && apps.length < 1000 && <button className="btn" onClick={() => void load(after)}>{t('investigation.more')}</button>}
    {error && <p role="alert">{t('errors.apiUnreachable')}</p>}
  </div>;
};
