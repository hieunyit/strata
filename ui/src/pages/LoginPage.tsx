import React, { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Languages } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { StrataMark } from '../components/layout/AppShell';
import { ApiError } from '../api/client';

// A local account: username and password checked by the control plane.
const PasswordForm: React.FC = () => {
  const { t } = useTranslation();
  const { loginWithPassword } = useAuth();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [mfa,setMfa] = useState(false);
  const [code,setCode] = useState('');
  const [recovery,setRecovery] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError('');
    try {
      await loginWithPassword(username.trim(), password,code,recovery);
    } catch (err) {
      const code = err instanceof ApiError ? err.code : 0;
      if (err instanceof ApiError && err.reason==='MFA_REQUIRED') {
        setMfa(true);setError(t('security.mfaRequired'));
      } else {
        setError(code === 401 ? t('login.badCredentials') : code === 429 ? t('login.throttled') : t('login.failed'));
        setPassword('');
      }
      setCode('');
      setBusy(false);
    }
  };

  return (
    <form onSubmit={submit} data-testid="password-login-form" className="mt-6 space-y-3">
      <div>
        <label htmlFor="login-username" className="label">{t('login.username')}</label>
        <input
          id="login-username"
          data-testid="login-username"
          className="field h-10"
          autoComplete="username"
          autoCapitalize="none"
          spellCheck={false}
          required
          value={username}
          onChange={(e) => setUsername(e.target.value)}
        />
      </div>
      <div>
        <label htmlFor="login-password" className="label">{t('login.password')}</label>
        <input
          id="login-password"
          data-testid="login-password"
          type="password"
          className="field h-10"
          autoComplete="current-password"
          required
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
      </div>
      {mfa && <div>
        <label htmlFor="login-code" className="label">{t(recovery?'security.recoveryCode':'security.code')}</label>
        <input id="login-code" data-testid="login-code" className="field h-10" autoComplete="one-time-code" maxLength={64} required value={code} onChange={e=>setCode(e.target.value.trim())}/>
        <label className="flex gap-2 text-sm mt-2"><input type="checkbox" checked={recovery} onChange={e=>setRecovery(e.target.checked)}/>{t('security.useRecovery')}</label>
      </div>}
      {error && (
        <p data-testid="password-login-error" role="alert" className="text-[13px] text-block">{error}</p>
      )}
      <button type="submit" data-testid="password-login-btn" disabled={busy || !username.trim() || !password} className="btn-primary h-10 w-full text-sm">
        {busy ? t('login.signingIn') : t('login.submit')}
      </button>
    </form>
  );
};

// Shown until the user has a session: a local account's password form
// and/or single sign-on, which redirects to the OIDC provider
// (authorization code with PKCE), as GET /v1/auth/methods allows.
export const LoginPage: React.FC = () => {
  const { t, i18n } = useTranslation();
  const { status, error, login, methods } = useAuth();
  const lang = i18n.language.startsWith('vi') ? 'vi' : 'en';

  return (
    <div className="min-h-screen grid lg:grid-cols-[minmax(0,1fr)_minmax(0,1.1fr)] bg-paper">
      <div className="hidden lg:flex flex-col justify-between bg-rail p-10 text-rail-ink">
        <div className="flex items-center gap-3">
          <StrataMark className="w-9 h-9" />
          <span className="text-lg font-semibold text-white">Strata</span>
        </div>
        <div className="max-w-md">
          <p className="text-[26px] leading-snug font-medium text-white">{t('login.tagline')}</p>
          <p className="mt-3 text-[13px] text-rail-ink/75">{t('login.taglineNote')}</p>
        </div>
        <svg viewBox="0 0 400 60" className="w-full max-w-md" aria-hidden>
          <path d="M0 18 C80 8 160 26 240 16 S360 8 400 14 V24 C330 20 260 30 180 24 S60 20 0 28Z" fill="rgb(var(--other))" opacity=".9" />
          <path d="M0 28 C60 20 180 24 180 24 C260 30 330 20 400 24 V38 C320 34 250 44 160 38 S50 34 0 42Z" fill="rgb(var(--shadow))" />
          <path d="M0 42 C50 34 160 38 160 38 C250 44 320 34 400 38 V54 C300 50 220 58 140 52 S40 50 0 56Z" fill="rgb(var(--block))" />
        </svg>
      </div>

      <div className="flex items-center justify-center px-6 py-12">
        <div className="w-full max-w-sm">
          <div className="lg:hidden mb-8 flex items-center gap-3">
            <StrataMark className="w-8 h-8" />
            <span className="text-lg font-semibold">Strata</span>
          </div>
          <h1 className="text-[22px] font-semibold">{t('login.title')}</h1>
          <p className="mt-1 text-[13px] text-muted">
            {methods.local ? (methods.oidc ? t('login.subtitleBoth') : t('login.subtitleLocal')) : t('login.subtitle')}
          </p>

          {status === 'loading' && (
            <p data-testid="login-loading" className="mt-6 text-[13px] text-muted">
              {t('login.loading')}
            </p>
          )}
          {status === 'error' && (
            <p data-testid="login-error" role="alert" className="mt-6 text-[13px] text-block">
              {t('login.error', { error })}
            </p>
          )}

          {status === 'anonymous' && methods.local && <PasswordForm />}

          {status === 'anonymous' && methods.local && methods.oidc && (
            <div className="my-5 flex items-center gap-3 text-xs text-faint" aria-hidden>
              <span className="h-px flex-1 bg-line" />
              {t('login.or')}
              <span className="h-px flex-1 bg-line" />
            </div>
          )}

          {((status === 'anonymous' && methods.oidc) || status === 'error') && (
            <button
              type="button"
              data-testid="login-btn"
              onClick={status === 'error' ? () => window.location.reload() : login}
              className={`${methods.local && status !== 'error' ? 'btn w-full justify-center' : 'btn-primary mt-6 w-full'} h-10 text-sm`}
            >
              {status === 'error' ? t('login.retry') : t('login.button')}
            </button>
          )}

          <button
            type="button"
            onClick={() => void i18n.changeLanguage(lang === 'en' ? 'vi' : 'en')}
            data-testid="login-language-btn"
            className="mt-6 inline-flex items-center gap-1.5 text-xs text-muted hover:text-ink"
          >
            <Languages className="w-3.5 h-3.5" />
            {lang === 'en' ? 'Tiếng Việt' : 'English'}
          </button>
        </div>
      </div>
    </div>
  );
};
