import React, { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { UserPlus, X, Bot, Key, Copy, Check, Trash2, Shield } from 'lucide-react';
import { apiClient, ApiError, LocalUser, ServiceAccount, ServiceAccountToken, CreateTokenResponse } from '../api/client';
import { useAuth, UserRole } from '../context/AuthContext';
import { PageShell } from './PageShell';
import { PageHeader, ErrorBanner, formatTime } from '../components/ui';

const ROLES: UserRole[] = ['viewer', 'operator', 'approver', 'admin'];
const MIN_PASSWORD = 12;

const SCOPES = [
  { id: 'policies:read', label: 'policies:read' },
  { id: 'policies:write', label: 'policies:write' },
  { id: 'rules:read', label: 'rules:read' },
  { id: 'rules:write', label: 'rules:write' },
  { id: 'events:read', label: 'events:read' },
  { id: 'service_accounts:read', label: 'service_accounts:read' },
  { id: 'service_accounts:write', label: 'service_accounts:write' },
  { id: 'system:admin', label: 'system:admin (Full Access)' },
];

const errorText = (e: unknown): string => (e instanceof Error ? e.message : String(e));

const RoleChecks: React.FC<{ value: string[]; onChange: (v: string[]) => void; idPrefix: string }> = ({ value, onChange, idPrefix }) => {
  const { t } = useTranslation();
  return (
    <fieldset className="flex flex-wrap gap-x-4 gap-y-1">
      <legend className="label">{t('users.roles')}</legend>
      {ROLES.map((r) => (
        <label key={r} className="inline-flex items-center gap-1.5 text-[13px]">
          <input
            type="checkbox"
            data-testid={`${idPrefix}-role-${r}`}
            checked={value.includes(r)}
            onChange={(e) => onChange(e.target.checked ? [...value, r] : value.filter((x) => x !== r))}
          />
          {t(`header.roles.${r}`)}
        </label>
      ))}
    </fieldset>
  );
};

const CreateUser: React.FC<{ onDone: () => void; onCancel: () => void }> = ({ onDone, onCancel }) => {
  const { t } = useTranslation();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [roles, setRoles] = useState<string[]>(['viewer']);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError('');
    try {
      await apiClient.createUser({ username: username.trim().toLowerCase(), password, roles: roles as UserRole[] });
      onDone();
    } catch (err) {
      setError(errorText(err));
      setBusy(false);
    }
  };

  return (
    <form onSubmit={submit} data-testid="create-user-form" className="panel mb-6 p-4 space-y-3">
      <div className="flex items-center justify-between">
        <h2 className="text-[15px] font-semibold">{t('users.create')}</h2>
        <button type="button" onClick={onCancel} aria-label={t('common.cancel')} className="p-1 text-muted hover:text-ink">
          <X className="w-4 h-4" />
        </button>
      </div>
      <div className="grid gap-3 sm:grid-cols-2">
        <div>
          <label htmlFor="new-username" className="label">{t('users.username')}</label>
          <input id="new-username" data-testid="new-username" className="field" autoComplete="off" spellCheck={false}
            required value={username} onChange={(e) => setUsername(e.target.value)} />
        </div>
        <div>
          <label htmlFor="new-password" className="label">{t('users.password', { min: MIN_PASSWORD })}</label>
          <input id="new-password" data-testid="new-password" type="password" className="field" autoComplete="new-password"
            required minLength={MIN_PASSWORD} value={password} onChange={(e) => setPassword(e.target.value)} />
        </div>
      </div>
      <RoleChecks value={roles} onChange={setRoles} idPrefix="new" />
      {error && <p role="alert" data-testid="create-user-error" className="text-[13px] text-block">{error}</p>}
      <div className="flex gap-2">
        <button type="submit" data-testid="create-user-btn" className="btn-primary" disabled={busy || !username.trim() || password.length < MIN_PASSWORD}>
          {t('users.createBtn')}
        </button>
        <button type="button" className="btn" onClick={onCancel}>{t('common.cancel')}</button>
      </div>
    </form>
  );
};

// One account's editor: roles, disabled, a new password, unlock, delete.
const EditUser: React.FC<{ user: LocalUser; self: boolean; onDone: () => void; onCancel: () => void }> = ({ user, self, onDone, onCancel }) => {
  const { t } = useTranslation();
  const [roles, setRoles] = useState<string[]>(user.roles);
  const [disabled, setDisabled] = useState(user.disabled);
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  const run = async (f: () => Promise<unknown>) => {
    setBusy(true);
    setError('');
    try {
      await f();
      onDone();
    } catch (err) {
      setError(errorText(err));
      setBusy(false);
    }
  };

  const save = (e: React.FormEvent) => {
    e.preventDefault();
    void run(() =>
      apiClient.updateUser(user.username, {
        roles: roles as UserRole[],
        disabled,
        ...(password ? { password } : {}),
      }),
    );
  };

  return (
    <form onSubmit={save} data-testid="edit-user-form" data-user={user.username} className="panel mb-6 p-4 space-y-3">
      <div className="flex items-center justify-between">
        <h2 className="text-[15px] font-semibold">{t('users.edit', { name: user.username })}</h2>
        <button type="button" onClick={onCancel} aria-label={t('common.cancel')} className="p-1 text-muted hover:text-ink">
          <X className="w-4 h-4" />
        </button>
      </div>
      <RoleChecks value={roles} onChange={setRoles} idPrefix="edit" />
      <label className="inline-flex items-center gap-1.5 text-[13px]">
        <input type="checkbox" data-testid="edit-disabled" checked={disabled} disabled={self} onChange={(e) => setDisabled(e.target.checked)} />
        {t('users.disabledLabel')}
      </label>
      <div className="max-w-sm">
        <label htmlFor="edit-password" className="label">{t('users.resetPassword', { min: MIN_PASSWORD })}</label>
        <input id="edit-password" data-testid="edit-password" type="password" className="field" autoComplete="new-password"
          minLength={MIN_PASSWORD} value={password} onChange={(e) => setPassword(e.target.value)} />
      </div>
      {error && <p role="alert" data-testid="edit-user-error" className="text-[13px] text-block">{error}</p>}
      <div className="flex flex-wrap gap-2">
        <button type="submit" data-testid="save-user-btn" className="btn-primary" disabled={busy || (password !== '' && password.length < MIN_PASSWORD)}>
          {t('users.save')}
        </button>
        {user.locked && (
          <button type="button" data-testid="unlock-user-btn" className="btn" disabled={busy}
            onClick={() => void run(() => apiClient.updateUser(user.username, { unlock: true }))}>
            {t('users.unlock')}
          </button>
        )}
        {!self && (
          <button type="button" data-testid="delete-user-btn" className="btn text-block ml-auto" disabled={busy}
            onClick={() => {
              if (window.confirm(t('users.deleteConfirm', { name: user.username }))) void run(() => apiClient.deleteUser(user.username));
            }}>
            {t('users.delete')}
          </button>
        )}
      </div>
    </form>
  );
};

// Manage Service Account Tokens
const ManageTokensModal: React.FC<{
  sa: ServiceAccount;
  onClose: () => void;
}> = ({ sa, onClose }) => {
  const { i18n } = useTranslation();
  const [tokens, setTokens] = useState<ServiceAccountToken[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [tokenName, setTokenName] = useState('');
  const [selectedScopes, setSelectedScopes] = useState<string[]>(['policies:read', 'events:read']);
  const [ttlDays, setTtlDays] = useState(30);
  const [generatedToken, setGeneratedToken] = useState<CreateTokenResponse | null>(null);
  const [copied, setCopied] = useState(false);
  const [generating, setGenerating] = useState(false);

  const loadTokens = useCallback(async () => {
    try {
      setTokens(await apiClient.listServiceAccountTokens(sa.id));
      setError('');
    } catch (e) {
      setError(errorText(e));
    } finally {
      setLoading(false);
    }
  }, [sa.id]);

  useEffect(() => {
    void loadTokens();
  }, [loadTokens]);

  const handleGenerate = async (e: React.FormEvent) => {
    e.preventDefault();
    setGenerating(true);
    setError('');
    try {
      const res = await apiClient.createServiceAccountToken(sa.id, {
        scopes: selectedScopes,
        ttl_seconds: ttlDays * 86400,
      });
      setGeneratedToken(res);
      setTokenName('');
      void loadTokens();
    } catch (e) {
      setError(errorText(e));
    } finally {
      setGenerating(false);
    }
  };

  const handleRevoke = async (tokenId: string) => {
    if (!window.confirm('Revoke this token immediately? Any running automation using it will be unauthorized.')) return;
    try {
      await apiClient.revokeServiceAccountToken(sa.id, tokenId);
      void loadTokens();
    } catch (e) {
      setError(errorText(e));
    }
  };

  const copyToClipboard = () => {
    if (generatedToken?.raw_token) {
      void navigator.clipboard.writeText(generatedToken.raw_token);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-ink/40 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="bg-paper border border-line rounded-lg shadow-xl w-full max-w-2xl max-h-[90vh] overflow-y-auto p-5 space-y-4">
        <div className="flex items-center justify-between border-b border-line pb-3">
          <div className="flex items-center gap-2">
            <Key className="w-5 h-5 text-accent" />
            <h2 className="text-base font-semibold">Tokens for {sa.name}</h2>
          </div>
          <button type="button" onClick={onClose} className="p-1 text-muted hover:text-ink">
            <X className="w-5 h-5" />
          </button>
        </div>

        {error && <ErrorBanner message={error} />}

        {generatedToken && (
          <div className="p-3.5 bg-sunken rounded border border-accent/40 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-accent flex items-center gap-1.5">
                <Shield className="w-4 h-4" />
                Token Generated Successfully (Copy now — it will not be shown again!)
              </span>
            </div>
            <div className="flex items-center gap-2">
              <input
                type="text"
                readOnly
                value={generatedToken.raw_token}
                className="field font-mono text-xs select-all bg-paper"
              />
              <button
                type="button"
                onClick={copyToClipboard}
                className="btn inline-flex items-center gap-1.5 whitespace-nowrap text-xs"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-ok" /> : <Copy className="w-3.5 h-3.5" />}
                {copied ? 'Copied!' : 'Copy'}
              </button>
            </div>
          </div>
        )}

        <form onSubmit={handleGenerate} className="p-3.5 bg-sunken/40 rounded border border-line space-y-3" data-testid="generate-token-form">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-muted">Generate New Token</h3>
          <div className="grid sm:grid-cols-2 gap-3">
            <div>
              <label className="label" htmlFor="tok-name">Token Name / Description</label>
              <input
                id="tok-name"
                data-testid="token-name"
                className="field text-xs"
                placeholder="e.g. CI/CD Release Pipeline"
                value={tokenName}
                onChange={(e) => setTokenName(e.target.value)}
                required
              />
            </div>
            <div>
              <label className="label" htmlFor="tok-ttl">TTL (Expiration)</label>
              <select
                id="tok-ttl"
                className="field text-xs"
                value={ttlDays}
                onChange={(e) => setTtlDays(Number(e.target.value))}
              >
                <option value={7}>7 Days</option>
                <option value={30}>30 Days (Recommended)</option>
                <option value={90}>90 Days</option>
                <option value={365}>1 Year</option>
              </select>
            </div>
          </div>

          <fieldset className="space-y-1">
            <legend className="label">Allowed Scopes</legend>
            <div className="grid grid-cols-2 gap-1.5 text-xs">
              {SCOPES.map((s) => (
                <label key={s.id} className="flex items-center gap-1.5">
                  <input
                    type="checkbox"
                    checked={selectedScopes.includes(s.id)}
                    onChange={(e) =>
                      setSelectedScopes(
                        e.target.checked ? [...selectedScopes, s.id] : selectedScopes.filter((x) => x !== s.id)
                      )
                    }
                  />
                  <span>{s.label}</span>
                </label>
              ))}
            </div>
          </fieldset>

          <button
            type="submit"
            className="btn-primary text-xs"
            disabled={generating || !tokenName.trim() || selectedScopes.length === 0}
            data-testid="generate-token-btn"
          >
            {generating ? 'Generating…' : 'Generate Token'}
          </button>
        </form>

        <div className="space-y-2">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-muted">Active Tokens</h3>
          {loading && <p className="text-xs text-muted">Loading tokens…</p>}
          {!loading && tokens.length === 0 && (
            <p className="text-xs text-muted py-2">No tokens issued for this service account.</p>
          )}
          {!loading && tokens.length > 0 && (
            <div className="border border-line rounded overflow-hidden">
              <table className="w-full text-xs">
                <thead>
                  <tr className="bg-sunken border-b border-line text-left">
                    <th className="p-2 font-medium">Token ID</th>
                    <th className="p-2 font-medium">Prefix</th>
                    <th className="p-2 font-medium">Scopes</th>
                    <th className="p-2 font-medium">Expires</th>
                    <th className="p-2 font-medium text-right">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {tokens.map((tok) => (
                    <tr key={tok.id} className="border-b border-line last:border-0 hover:bg-sunken/20">
                      <td className="p-2 font-mono text-muted">{tok.id}</td>
                      <td className="p-2 font-mono text-ink font-semibold">{tok.token_prefix}…</td>
                      <td className="p-2 text-muted">{tok.scopes?.join(', ') || 'none'}</td>
                      <td className="p-2 text-muted whitespace-nowrap">
                        {tok.revoked ? (
                          <span className="text-block font-semibold">Revoked</span>
                        ) : (
                          formatTime(tok.expires_at, i18n.language, 'never')
                        )}
                      </td>
                      <td className="p-2 text-right">
                        {!tok.revoked && (
                          <button
                            type="button"
                            onClick={() => handleRevoke(tok.id)}
                            className="btn text-block text-[11px] py-0.5 px-2"
                            data-testid="revoke-token-btn"
                          >
                            Revoke
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export const UsersPage: React.FC = () => {
  const { t, i18n } = useTranslation();
  const { username, roles, methods } = useAuth();
  const canWrite = roles.includes('admin');
  const [activeTab, setActiveTab] = useState<'users' | 'service_accounts'>('users');

  // Users State
  const [users, setUsers] = useState<LocalUser[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [mode, setMode] = useState<{ kind: 'none' } | { kind: 'create' } | { kind: 'edit'; name: string }>({ kind: 'none' });

  // Service Accounts State
  const [serviceAccounts, setServiceAccounts] = useState<ServiceAccount[]>([]);
  const [saLoading, setSaLoading] = useState(false);
  const [saError, setSaError] = useState('');
  const [createSaOpen, setCreateSaOpen] = useState(false);
  const [saName, setSaName] = useState('');
  const [saDesc, setSaDesc] = useState('');
  const [activeSaForTokens, setActiveSaForTokens] = useState<ServiceAccount | null>(null);

  const loadUsers = useCallback(async () => {
    try {
      setUsers(await apiClient.listUsers());
      setError('');
    } catch (err) {
      setError(err instanceof ApiError && err.code === 404 ? t('users.notEnabled') : errorText(err));
    } finally {
      setLoading(false);
    }
  }, [t]);

  const loadServiceAccounts = useCallback(async () => {
    setSaLoading(true);
    try {
      setServiceAccounts(await apiClient.listServiceAccounts());
      setSaError('');
    } catch (err) {
      setSaError(errorText(err));
    } finally {
      setSaLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadUsers();
    if (canWrite) {
      void loadServiceAccounts();
    }
  }, [loadUsers, loadServiceAccounts, canWrite]);

  const doneUser = () => {
    setMode({ kind: 'none' });
    void loadUsers();
  };

  const handleCreateSa = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!saName.trim()) return;
    try {
      await apiClient.createServiceAccount({ name: saName.trim(), description: saDesc.trim() });
      setSaName('');
      setSaDesc('');
      setCreateSaOpen(false);
      void loadServiceAccounts();
    } catch (e) {
      setSaError(errorText(e));
    }
  };

  const handleDeleteSa = async (sa: ServiceAccount) => {
    if (!window.confirm(`Delete service account "${sa.name}"? All its tokens will be invalidated.`)) return;
    try {
      await apiClient.deleteServiceAccount(sa.id);
      void loadServiceAccounts();
    } catch (e) {
      setSaError(errorText(e));
    }
  };

  const editing = mode.kind === 'edit' ? users.find((u) => u.username === mode.name) : undefined;
  const never = t('users.never');

  return (
    <PageShell active="users">
      <PageHeader
        title={t('users.title')}
        description={methods.oidc ? t('users.subtitleBoth') : t('users.subtitle')}
        actions={
          canWrite && (
            <div className="flex gap-2">
              {activeTab === 'users' && mode.kind === 'none' && (
                <button type="button" data-testid="new-user-btn" className="btn-primary" onClick={() => setMode({ kind: 'create' })}>
                  <UserPlus className="w-3.5 h-3.5" />
                  {t('users.create')}
                </button>
              )}
              {activeTab === 'service_accounts' && !createSaOpen && (
                <button type="button" data-testid="new-sa-btn" className="btn-primary" onClick={() => setCreateSaOpen(true)}>
                  <Bot className="w-3.5 h-3.5" />
                  New Service Account
                </button>
              )}
            </div>
          )
        }
      />

      {/* Account Type Tabs */}
      <div className="flex gap-2 border-b border-line mb-4 pb-1">
        <button
          type="button"
          onClick={() => setActiveTab('users')}
          className={`px-3 py-1.5 text-xs font-medium rounded-t border-b-2 transition-colors ${
            activeTab === 'users'
              ? 'border-accent text-ink font-semibold'
              : 'border-transparent text-muted hover:text-ink'
          }`}
          data-testid="tab-users"
        >
          User Accounts
        </button>
        {canWrite && (
          <button
            type="button"
            onClick={() => {
              setActiveTab('service_accounts');
              void loadServiceAccounts();
            }}
            className={`px-3 py-1.5 text-xs font-medium rounded-t border-b-2 transition-colors ${
              activeTab === 'service_accounts'
                ? 'border-accent text-ink font-semibold'
                : 'border-transparent text-muted hover:text-ink'
            }`}
            data-testid="tab-service-accounts"
          >
            Service Accounts (M2M)
          </button>
        )}
      </div>

      <ErrorBanner message={error || saError} />

      {/* Tab 1: User Accounts */}
      {activeTab === 'users' && (
        <>
          {mode.kind === 'create' && <CreateUser onDone={doneUser} onCancel={() => setMode({ kind: 'none' })} />}
          {editing && (
            <EditUser key={editing.username} user={editing} self={editing.username === username} onDone={doneUser} onCancel={() => setMode({ kind: 'none' })} />
          )}
          {loading && <p className="text-[13px] text-muted">{t('users.loading')}</p>}
          {!loading && !error && (
            <div className="panel overflow-x-auto">
              <table className="w-full text-[13px]" data-testid="users-table">
                <thead>
                  <tr className="border-b border-line bg-sunken/50">
                    <th className="th">{t('users.col.user')}</th>
                    <th className="th">{t('users.col.roles')}</th>
                    <th className="th">{t('users.col.status')}</th>
                    <th className="th">{t('users.col.lastLogin')}</th>
                    <th className="th">{t('users.col.created')}</th>
                    {canWrite && <th className="th"><span className="sr-only">{t('users.col.actions')}</span></th>}
                  </tr>
                </thead>
                <tbody>
                  {users.length === 0 && (
                    <tr><td colSpan={6} className="td py-6 text-center text-muted" data-testid="users-empty">{t('users.empty')}</td></tr>
                  )}
                  {users.map((u) => {
                    const state = u.disabled ? 'disabled' : u.locked ? 'locked' : 'active';
                    return (
                      <tr key={u.username} data-testid="user-row" data-user={u.username} data-state={state} className="border-b border-line last:border-0">
                        <td className="td font-medium">
                          {u.username}
                          {u.username === username && <span className="ml-2 text-xs font-normal text-muted">{t('users.you')}</span>}
                        </td>
                        <td className="td text-muted">{u.roles.map((r) => t(`header.roles.${r}`)).join(', ') || t('header.roles.none')}</td>
                        <td className="td">
                          <span className={state === 'active' ? 'text-ok' : 'text-block'} data-testid="user-state">{t(`users.state.${state}`)}</span>
                        </td>
                        <td className="td text-muted whitespace-nowrap">{formatTime(u.last_login_at, i18n.language, never)}</td>
                        <td className="td text-muted whitespace-nowrap">
                          {formatTime(u.created_at, i18n.language, never)}
                          <div className="text-xs text-faint">{u.created_by}</div>
                        </td>
                        {canWrite && (
                          <td className="td text-right">
                            <button type="button" data-testid="edit-user-btn" className="btn" onClick={() => setMode({ kind: 'edit', name: u.username })}>
                              {t('users.editBtn')}
                            </button>
                          </td>
                        )}
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}

      {/* Tab 2: Service Accounts */}
      {activeTab === 'service_accounts' && canWrite && (
        <div className="space-y-4">
          {createSaOpen && (
            <form onSubmit={handleCreateSa} className="panel p-4 space-y-3" data-testid="create-sa-form">
              <div className="flex items-center justify-between">
                <h2 className="text-[15px] font-semibold">New Service Account</h2>
                <button type="button" onClick={() => setCreateSaOpen(false)} className="p-1 text-muted hover:text-ink">
                  <X className="w-4 h-4" />
                </button>
              </div>
              <div className="grid gap-3 sm:grid-cols-2">
                <div>
                  <label htmlFor="sa-name" className="label">Name</label>
                  <input
                    id="sa-name"
                    data-testid="sa-name"
                    className="field text-xs"
                    placeholder="e.g. terraform-provider"
                    value={saName}
                    onChange={(e) => setSaName(e.target.value)}
                    required
                  />
                </div>
                <div>
                  <label htmlFor="sa-desc" className="label">Description</label>
                  <input
                    id="sa-desc"
                    data-testid="sa-description"
                    className="field text-xs"
                    placeholder="e.g. Automated policy rollout pipeline"
                    value={saDesc}
                    onChange={(e) => setSaDesc(e.target.value)}
                  />
                </div>
              </div>
              <div className="flex gap-2">
                <button type="submit" className="btn-primary text-xs" disabled={!saName.trim()} data-testid="create-sa-submit">
                  Create Service Account
                </button>
                <button type="button" className="btn text-xs" onClick={() => setCreateSaOpen(false)}>
                  Cancel
                </button>
              </div>
            </form>
          )}

          {saLoading && <p className="text-[13px] text-muted">Loading service accounts…</p>}

          {!saLoading && (
            <div className="panel overflow-x-auto">
              <table className="w-full text-[13px]" data-testid="sa-table">
                <thead>
                  <tr className="border-b border-line bg-sunken/50">
                    <th className="th">Service Account</th>
                    <th className="th">Description</th>
                    <th className="th">Created</th>
                    <th className="th">Created By</th>
                    <th className="th text-right">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {serviceAccounts.length === 0 && (
                    <tr>
                      <td colSpan={5} className="td py-6 text-center text-muted" data-testid="sa-empty">
                        No service accounts created yet.
                      </td>
                    </tr>
                  )}
                  {serviceAccounts.map((sa) => (
                    <tr key={sa.id} data-testid="sa-row" className="border-b border-line last:border-0 hover:bg-sunken/20">
                      <td className="td font-medium flex items-center gap-2">
                        <Bot className="w-4 h-4 text-accent" />
                        <span>{sa.name}</span>
                      </td>
                      <td className="td text-muted">{sa.description || '—'}</td>
                      <td className="td text-muted whitespace-nowrap">{formatTime(sa.created_at, i18n.language, never)}</td>
                      <td className="td text-muted">{sa.created_by}</td>
                      <td className="td text-right">
                        <span className="inline-flex gap-2">
                          <button
                            type="button"
                            onClick={() => setActiveSaForTokens(sa)}
                            className="btn inline-flex items-center gap-1.5 text-xs"
                            data-testid="manage-tokens-btn"
                          >
                            <Key className="w-3.5 h-3.5" />
                            Tokens ({sa.token_count ?? 0})
                          </button>
                          <button
                            type="button"
                            onClick={() => handleDeleteSa(sa)}
                            className="btn text-block text-xs"
                            data-testid="delete-sa-btn"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {activeSaForTokens && (
            <ManageTokensModal sa={activeSaForTokens} onClose={() => { setActiveSaForTokens(null); void loadServiceAccounts(); }} />
          )}
        </div>
      )}
    </PageShell>
  );
};
