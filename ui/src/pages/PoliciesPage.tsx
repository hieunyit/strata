import React, { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { apiClient, Policy, PolicyVersion } from '../api/client';
import { usePolling } from '../usePolling';
import { PageShell, ErrorBanner, formatTime } from './PageShell';

const modeClass: Record<string, string> = {
  MODE_ENFORCE: 'bg-rose-100 text-rose-800 dark:bg-rose-950 dark:text-rose-300',
  MODE_SHADOW: 'bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300',
};

// Read only (W04-F-01): editing, diff and deploy come with the policy editor.
export const PoliciesPage: React.FC = () => {
  const { t, i18n } = useTranslation();
  const { data, error, loading } = usePolling(() => apiClient.listPolicies(), 0);
  const [selected, setSelected] = useState<Policy | null>(null);
  const [versions, setVersions] = useState<PolicyVersion[]>([]);
  const [versionsError, setVersionsError] = useState<string | undefined>();

  const open = async (p: Policy) => {
    setSelected(p);
    setVersions([]);
    setVersionsError(undefined);
    try {
      setVersions(await apiClient.listPolicyVersions(p.id ?? ''));
    } catch (e) {
      setVersionsError(e instanceof Error ? e.message : String(e));
    }
  };

  const mode = (m?: string) => (
    <span className={`px-2 py-0.5 rounded text-xs font-medium ${modeClass[m ?? ''] ?? 'bg-slate-100 text-slate-600'}`}>
      {t(`policies.mode.${m ?? 'MODE_UNSPECIFIED'}`)}
    </span>
  );

  return (
    <PageShell active="policies">
      <h1 className="text-xl font-semibold text-slate-900 dark:text-white">{t('policies.title')}</h1>
      <p className="text-sm text-slate-500 dark:text-slate-400 mb-6">{t('policies.subtitle')}</p>
      <ErrorBanner message={error && t('common.refreshError', { error })} />
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl overflow-hidden">
        <table className="w-full text-sm" data-testid="policies-table">
          <thead className="bg-slate-50 dark:bg-slate-800/60 text-left text-xs uppercase text-slate-500">
            <tr>
              <th className="px-4 py-2">{t('policies.col.name')}</th>
              <th className="px-4 py-2">{t('policies.col.mode')}</th>
              <th className="px-4 py-2">{t('policies.col.oversize')}</th>
              <th className="px-4 py-2">{t('policies.col.version')}</th>
              <th className="px-4 py-2">{t('policies.col.updated')}</th>
              <th className="px-4 py-2">{t('policies.col.by')}</th>
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr><td colSpan={6} className="px-4 py-6 text-center text-slate-500">{t('policies.loading')}</td></tr>
            )}
            {!loading && (data ?? []).length === 0 && (
              <tr><td colSpan={6} className="px-4 py-6 text-center text-slate-500" data-testid="policies-empty">{t('policies.empty')}</td></tr>
            )}
            {(data ?? []).map((p) => (
              <tr
                key={p.id}
                data-testid="policy-row"
                onClick={() => void open(p)}
                className={`border-t border-slate-100 dark:border-slate-800 cursor-pointer hover:bg-slate-50 dark:hover:bg-slate-800/40 ${selected?.id === p.id ? 'bg-sky-50 dark:bg-sky-950/30' : ''}`}
              >
                <td className="px-4 py-2 font-medium text-slate-900 dark:text-white">{p.name}</td>
                <td className="px-4 py-2">{mode(p.spec?.mode)}</td>
                <td className="px-4 py-2 text-slate-600 dark:text-slate-300">{t(`policies.oversize.${p.spec?.oversize ?? 'OVERSIZE_UNSPECIFIED'}`)}</td>
                <td className="px-4 py-2 tabular-nums" data-testid="policy-version">{p.version}</td>
                <td className="px-4 py-2 text-slate-500">{formatTime(p.update_time, i18n.language, t('common.never'))}</td>
                <td className="px-4 py-2 text-slate-500">{p.created_by}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {selected && (
        <section className="mt-6" data-testid="policy-versions">
          <h2 className="text-sm font-semibold text-slate-700 dark:text-slate-200 mb-2">{t('policies.versions', { name: selected.name })}</h2>
          <ErrorBanner message={versionsError && t('common.refreshError', { error: versionsError })} />
          <ol className="space-y-1 text-sm">
            {versions.map((v) => (
              <li key={v.version} data-testid="policy-version-row" className="flex items-center gap-3 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-3 py-2">
                <span className="tabular-nums font-medium w-10">v{v.version}</span>
                {mode(v.spec?.mode)}
                <span className="text-slate-500">{formatTime(v.create_time, i18n.language, t('common.never'))}</span>
                <span className="text-slate-500 ml-auto">{v.created_by}</span>
              </li>
            ))}
          </ol>
        </section>
      )}
    </PageShell>
  );
};
