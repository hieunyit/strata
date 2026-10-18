import { ServiceAccountTokens as ManageTokensModal } from '../components/users/ServiceAccountTokens';
import React, { useCallback, useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { UserPlus, X, Bot, Key, Trash2 } from 'lucide-react';
import { apiClient, ApiError, LocalUser, ServiceAccount, CreateServiceAccountRequest } from '../api/client';
import { useAuth, UserRole } from '../context/AuthContext';
import { PageShell } from './PageShell';
import { PageHeader, ErrorBanner, formatTime } from '../components/ui';

const ROLES: UserRole[] = ['viewer', 'operator', 'approver', 'admin'];
const MIN_PASSWORD = 12;

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
 const [saRoles,setSaRoles]=useState<UserRole[]>(['viewer']);
  const [saBusy,setSaBusy]=useState(false);
  const [saPending,setSaPending]=useState(false);
  const saInFlight=useRef(false);
  const createCommand=useRef<CreateServiceAccountRequest>();
  const deleteCommands=useRef(new Map<string,{etag:string;requestId:string}>());
  const [activeSaForTokens, setActiveSaForTokens] = useState<ServiceAccount | null>(null);
  const saReadVersion=useRef(0);

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

  const loadServiceAccounts = useCallback(async (quiet=false) => {
    const version=++saReadVersion.current;
    if(!quiet)setSaLoading(true);
    try {
      const result=await apiClient.listServiceAccounts();
      if(version!==saReadVersion.current)return;
      setServiceAccounts(result);
      setSaError('');
    } catch (err) {
      if(version===saReadVersion.current)setSaError(errorText(err));
    } finally {
      if(version===saReadVersion.current)setSaLoading(false);
    }
  }, []);

  useEffect(() => {void loadUsers();},[loadUsers]);
  useEffect(() => {if(canWrite)void loadServiceAccounts();},[loadServiceAccounts,canWrite]);

  const doneUser = () => {
    setMode({ kind: 'none' });
    void loadUsers();
  };

  const handleCreateSa = async (e: React.FormEvent) => {
    e.preventDefault();if(saInFlight.current || !saName.trim())return;
    saInFlight.current=true;setSaBusy(true);setSaError('');
    try {
      createCommand.current??={id:`sa-${crypto.randomUUID()}`,name:saName.trim(),description:saDesc.trim(),roles:[...saRoles],request_id:crypto.randomUUID()};
      setSaPending(true);
      await apiClient.createServiceAccount(createCommand.current);
      createCommand.current=undefined;setSaPending(false);setSaName('');setSaDesc('');setCreateSaOpen(false);void loadServiceAccounts();
    } catch(e) {
      setSaError(errorText(e));
      if(e instanceof ApiError && e.code===400){createCommand.current=undefined;setSaPending(false);}
    } finally{saInFlight.current=false;setSaBusy(false);}
  };
  const handleDeleteSa = async (sa:ServiceAccount) => {
    if(saInFlight.current || !window.confirm(t('machine.deleteConfirm',{name:sa.name})))return;
    saInFlight.current=true;setSaBusy(true);setSaError('');
    try{
      let cmd=deleteCommands.current.get(sa.id);
      if(!cmd){cmd={etag:sa.etag,requestId:crypto.randomUUID()};deleteCommands.current.set(sa.id,cmd);}
      await apiClient.deleteServiceAccount(sa.id,cmd.etag,cmd.requestId);
      deleteCommands.current.delete(sa.id);void loadServiceAccounts();
    }catch(e){setSaError(errorText(e));}
    finally{saInFlight.current=false;setSaBusy(false);}
  };

  const editing = mode.kind === 'edit' ? users.find((u) => u.username === mode.name) : undefined;
  const never = t('users.never');

  return (
    <PageShell active="users">
      <PageHeader
        title={t(activeTab==='service_accounts'?'machine.accountsTab':'users.title')}
        description={activeTab==='service_accounts'?t('machine.subtitle'):methods.oidc ? t('users.subtitleBoth') : t('users.subtitle')}
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
                  {t('machine.new')}
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
          {t('machine.usersTab')}
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
            {t('machine.accountsTab')}
          </button>
        )}
      </div>

      <ErrorBanner message={activeTab === 'users' ? error : saError} />

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
                <h2 className="text-[15px] font-semibold">{t('machine.new')}</h2>
                <button type="button" disabled={saBusy} aria-label={t('machine.close')} onClick={() => setCreateSaOpen(false)} className="p-1 text-muted hover:text-ink">
                  <X className="w-4 h-4" />
                </button>
              </div>
              <div className="grid gap-3 sm:grid-cols-2">
                <div>
                  <label htmlFor="sa-name" className="label">{t('machine.name')}</label>
                  <input
                    disabled={saBusy || saPending}
                    maxLength={128}
                    id="sa-name"
                    data-testid="sa-name"
                    className="field text-xs"
                    placeholder={t('machine.nameExample')}
                    value={saName}
                    onChange={(e) => setSaName(e.target.value)}
                    required
                  />
                </div>
                <div>
                  <label htmlFor="sa-desc" className="label">{t('machine.description')}</label>
                  <input
                    disabled={saBusy || saPending}
 maxLength={2048}
 id="sa-desc"
                    data-testid="sa-description"
                    className="field text-xs"
                    placeholder={t('machine.descriptionExample')}
                    value={saDesc}
                    onChange={(e) => setSaDesc(e.target.value)}
                  />
                </div>
              </div>
              <fieldset disabled={saBusy || saPending}><RoleChecks value={saRoles} onChange={roles=>setSaRoles(roles as UserRole[])} idPrefix="machine"/></fieldset>
              <div className="flex gap-2">
                <button type="submit" className="btn-primary text-xs" disabled={saBusy || !saName.trim() || !saRoles.length} data-testid="create-sa-submit">
                  {t(saPending?'machine.retry':'machine.create')}
                </button>
                <button type="button" className="btn text-xs" onClick={() => setCreateSaOpen(false)}>
                  {t('machine.cancel')}
                </button>
              </div>
            </form>
          )}

          {saLoading && <p className="text-[13px] text-muted">{t('machine.loadingAccounts')}</p>}

          {!saLoading && (
            <div className="panel overflow-x-auto">
              <table className="w-full text-[13px]" data-testid="sa-table">
                <thead>
                  <tr className="border-b border-line bg-sunken/50">
                    <th className="th">{t('machine.account')}</th>
                    <th className="th hidden md:table-cell">{t('machine.description')}</th>
                    <th className="th hidden md:table-cell">{t('machine.created')}</th>
                    <th className="th hidden md:table-cell">{t('machine.createdBy')}</th>
                    <th className="th text-right">{t('machine.actions')}</th>
                  </tr>
                </thead>
                <tbody>
                  {serviceAccounts.length === 0 && (
                    <tr>
                      <td colSpan={5} className="td py-6 text-center text-muted" data-testid="sa-empty">
                        {t('machine.emptyAccounts')}
                      </td>
                    </tr>
                  )}
                  {serviceAccounts.map((sa) => (
                    <tr key={sa.id} data-testid="sa-row" className="border-b border-line last:border-0 hover:bg-sunken/20">
                      <td className="td font-medium">
                        <div className="flex items-center gap-2"><Bot className="w-4 h-4 shrink-0 text-accent" />
                        <span className="max-w-[12rem] break-all">{sa.name}</span></div>
                      </td>
                      <td className="td text-muted hidden md:table-cell">{sa.description || '—'}</td>
                      <td className="td text-muted whitespace-nowrap hidden md:table-cell">{formatTime(sa.created_at, i18n.language, never)}</td>
                      <td className="td text-muted hidden md:table-cell">{sa.created_by}</td>
                      <td className="td text-right">
                        <span className="inline-flex gap-2">
                          <button
                            type="button"
                            onClick={() => setActiveSaForTokens(sa)}
                            className="btn inline-flex items-center gap-1.5 text-xs"
                            data-testid="manage-tokens-btn"
                          >
                            <Key className="w-3.5 h-3.5" />
                            {t('machine.tokens',{count:sa.token_count ?? 0})}
                          </button>
                          <button
                            type="button"
                            disabled={saBusy}
 onClick={() => handleDeleteSa(sa)}
                            className="btn text-block text-xs"
                            aria-label={t('machine.deleteConfirm',{name:sa.name})}
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

          {canWrite && activeSaForTokens && (
            <ManageTokensModal key={activeSaForTokens.id} sa={activeSaForTokens} onClose={() => { setActiveSaForTokens(null); void loadServiceAccounts(true); }} />
          )}
        </div>
      )}
    </PageShell>
  );
};
