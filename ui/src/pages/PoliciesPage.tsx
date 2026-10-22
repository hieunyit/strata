import React, { useState, useRef, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { Download, GitCompare, Pencil } from 'lucide-react';
import { apiClient, Policy, PolicyVersion } from '../api/client';
import { usePolling } from '../usePolling';
import { downloadCsv, csvDate } from '../lib/csv';
import { PageShell } from './PageShell';
import { PageHeader, ErrorBanner, SectionTitle, Empty, formatTime, actorName } from '../components/ui';
import { href } from '../router';
import { useAuth } from '../context/AuthContext';
import { canWritePolicies } from '../auth/roles';
import { PolicyEditor } from '../components/policy/PolicyEditor';
import { NewPolicy } from '../components/policy/NewPolicy';
import { VersionReview } from '../components/policy/VersionReview';
import { PolicyDiff } from '../components/policy/PolicyDiff';

const modeClass: Record<string, string> = {
  MODE_ENFORCE: 'text-block border-block/30 bg-block/10',
  MODE_SHADOW: 'text-shadow border-shadow/35 bg-shadow/10',
};

// Policies and their versions; operators and admins edit a policy with the
// editor (W11-F-01), which saves a draft version; anyone who can read
// policies compares two versions block by block (W12-F-01). Deploy from
// the UI comes later.
export const PoliciesPage: React.FC = () => {
  const { t, i18n } = useTranslation();
  const { roles, scoped, policyPermissions } = useAuth();
  const canEdit = canWritePolicies(roles);
  const { data, error, loading, refresh } = usePolling(() => apiClient.listPolicies(), 0);
  const [reviewVersion, setReviewVersion] = useState<number>();
  const versionRead = useRef<AbortController>();
  const activePolicy = useRef<string>();
  useEffect(() => () => versionRead.current?.abort(), []);
  const [selected, setSelected] = useState<Policy | null>(null);
  const [editing, setEditing] = useState(false);
  const [creating, setCreating] = useState(false);
  const [comparing, setComparing] = useState(false);
  const [saved, setSaved] = useState<number | undefined>();
  const [versions, setVersions] = useState<PolicyVersion[]>([]);
  const [versionsError, setVersionsError] = useState<string | undefined>();

  const open = async (p: Policy) => {
    versionRead.current?.abort(); activePolicy.current = p.id;
    const controller = new AbortController(); versionRead.current = controller;
    setReviewVersion(undefined);
    setSelected(p);
    setEditing(false);
    setComparing(false);
    setSaved(undefined);
    setVersions([]);
    setVersionsError(undefined);
    try {
      const rows = await apiClient.listPolicyVersions(p.id ?? '', controller.signal);
      if (!controller.signal.aborted) setVersions(rows);
    } catch (e) {
      if (controller.signal.aborted) return;
      setVersionsError(e instanceof Error ? e.message : String(e));
    }
  };

  const mode = (m?: string) => (
    <span className={`inline-block rounded border px-1.5 py-0.5 text-xs font-medium ${modeClass[m ?? ''] ?? 'text-muted border-line'}`}>
      {t(`policies.mode.${m ?? 'MODE_UNSPECIFIED'}`)}
    </span>
  );

  const exportCsv = () => {
    const rows = (data ?? []).map((p) => [p.name ?? '', p.spec?.mode ?? '', p.spec?.oversize ?? '', p.version ?? 0, p.update_time ?? '', p.created_by ?? '']);
    downloadCsv(`strata-policies-${csvDate()}.csv`, ['Name', 'Mode', 'Oversize', 'Version', 'Updated', 'Updated by'], rows);
  };

  const list = data ?? [];
  return (
    <PageShell active="policies">
      <PageHeader
        title={t('policies.title')}
        description={t('policies.subtitle')}
        actions={
          <>
            {canEdit && !scoped && !creating && (
              <button type="button" data-testid="new-policy-btn" onClick={() => setCreating(true)} className="btn">
                {t('policies.new.open')}
              </button>
            )}
            {list.length > 0 && (
              <button type="button" data-testid="export-csv-btn" onClick={exportCsv} className="btn">
                <Download className="w-3.5 h-3.5" />
                {t('common.exportCsv')}
              </button>
            )}
          </>
        }
      />
      {creating && (
        <NewPolicy
          onCancel={() => setCreating(false)}
          onCreated={(p) => {
            setCreating(false);
            refresh();
            void open(p);
          }}
        />
      )}
      <ErrorBanner message={error && t('common.refreshError', { error })} />
      {saved !== undefined && (
        <p className="mb-3 text-[13px] text-ok" role="status" data-testid="editor-saved">
          {t('editor.saved', { version: saved })}
        </p>
      )}
      {editing && selected && (
        <div className="mb-5">
          <PolicyEditor
            policy={selected}
            onCancel={() => setEditing(false)}
            onSaved={(p) => {
              void refresh();
              void open(p).then(() => setSaved(p.version));
            }}
          />
        </div>
      )}
      {comparing && selected && versions.length >= 2 && (
        <div className="mb-5">
          <PolicyDiff name={selected.name ?? ''} versions={versions} onClose={() => setComparing(false)} />
        </div>
      )}
      {selected?.id && reviewVersion !== undefined && <div className="mb-5">
        <VersionReview key={`${selected.id}:${reviewVersion}`} policyId={selected.id} version={reviewVersion} onChanged={() => {
          void refresh();
          if (activePolicy.current !== selected.id) return;
          const signal = versionRead.current?.signal;
          void apiClient.listPolicyVersions(selected.id!, signal).then(rows => { if (!signal?.aborted) setVersions(rows); })
            .catch(() => { if (!signal?.aborted) setVersionsError(t('reviews.unavailable')); });
        }} />
      </div>}
      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_24rem]">
        <div className="panel overflow-x-auto">
          <table className="w-full text-[13px]" data-testid="policies-table">
            <thead>
              <tr className="border-b border-line bg-sunken/50">
                <th className="th">{t('policies.col.name')}</th>
                <th className="th">{t('policies.col.mode')}</th>
                <th className="th">{t('policies.col.oversize')}</th>
                <th className="th text-right">{t('policies.col.version')}</th>
                <th className="th">{t('policies.col.updated')}</th>
                <th className="th">{t('policies.col.by')}</th>
              </tr>
            </thead>
            <tbody>
              {loading && (
                <tr>
                  <td colSpan={6} className="td py-8 text-center text-muted">{t('policies.loading')}</td>
                </tr>
              )}
              {!loading && list.length === 0 && (
                <tr>
                  <td colSpan={6} className="td py-8 text-center text-muted" data-testid="policies-empty">{t('policies.empty')}</td>
                </tr>
              )}
              {list.map((p) => (
                <tr
                  key={p.id}
                  data-testid="policy-row"
                  tabIndex={0}
                  onClick={() => void open(p)}
                  onKeyDown={(e) => e.key === 'Enter' && void open(p)}
                  aria-selected={selected?.id === p.id}
                  className={`border-b border-line last:border-0 cursor-pointer hover:bg-sunken/70 ${selected?.id === p.id ? 'bg-accent/5' : ''}`}
                >
                  <td className="td font-medium">{p.name}</td>
                  <td className="td">{mode(p.spec?.mode)}</td>
                  <td className="td text-muted">{t(`policies.oversize.${p.spec?.oversize ?? 'OVERSIZE_UNSPECIFIED'}`)}</td>
                  <td className="td text-right tabular-nums" data-testid="policy-version">{p.version}</td>
                  <td className="td text-muted whitespace-nowrap">{formatTime(p.update_time, i18n.language, t('common.never'))}</td>
                  <td className="td text-muted" title={p.created_by}>{actorName(p.created_by)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <section className="panel self-start" data-testid={selected ? 'policy-versions' : undefined}>
          {selected ? (
            <>
              <SectionTitle
                aside={
                  <span className="flex items-center gap-3">
                    {versions.length >= 2 && !comparing && (
                      <button type="button" className="btn" onClick={() => setComparing(true)} data-testid="policy-compare">
                        <GitCompare className="w-3.5 h-3.5" />
                        {t('policies.compare')}
                      </button>
                    )}
                    {canEdit && (!scoped || policyPermissions?.[selected.id ?? '']?.includes('policies:write')) && !editing && (
                      <button type="button" className="btn" onClick={() => setEditing(true)} data-testid="policy-edit">
                        <Pencil className="w-3.5 h-3.5" />
                        {t('editor.edit')}
                      </button>
                    )}
                    <a className="text-accent hover:underline" href={href({ page: 'overview', query: { policy_id: selected.id ?? '' } })}>
                      {t('policies.openOverview')}
                    </a>
                  </span>
                }
              >
                {t('policies.versions', { name: selected.name })}
              </SectionTitle>
              <div className="px-4 pt-3">
                <ErrorBanner message={versionsError && t('common.refreshError', { error: versionsError })} />
              </div>
              <ol className="divide-y divide-line px-4 pb-2 text-[13px]">
                {versions.map((v) => (
                  <li key={v.version} data-testid="policy-version-row" className="flex flex-wrap items-center gap-3 py-2">
                    <span className="w-10 tabular-nums font-medium">v{v.version}</span>
                    <button type="button" className="btn" onClick={() => setReviewVersion(v.version)}>{t('reviews.inspect')}</button>
                    {mode(v.spec?.mode)}
                    {v.state && (
                      <span className="text-xs text-muted" data-testid="policy-version-state">{t(`editor.state.${v.state}`, { defaultValue: v.state })}</span>
                    )}
                    <span className="ml-auto text-right text-xs text-muted">
                      {formatTime(v.create_time, i18n.language, t('common.never'))}
                      {v.created_by && <div title={v.created_by}>{actorName(v.created_by)}</div>}
                    </span>
                  </li>
                ))}
              </ol>
            </>
          ) : (
            <Empty>{t('policies.pick')}</Empty>
          )}
        </section>
      </div>
    </PageShell>
  );
};
