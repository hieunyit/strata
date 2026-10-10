import React from 'react';
import { useTranslation } from 'react-i18next';
import { Shield, Globe } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

// Shown until the user has a session; signing in redirects to the OIDC
// provider (authorization code with PKCE).
export const LoginPage: React.FC = () => {
  const { t, i18n } = useTranslation();
  const { status, error, login } = useAuth();
  const toggleLanguage = () => i18n.changeLanguage(i18n.language.startsWith('vi') ? 'en' : 'vi');

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-50 dark:bg-slate-950 px-4">
      <div className="w-full max-w-sm bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl shadow-sm p-8 text-center">
        <div className="mx-auto w-12 h-12 rounded-xl bg-sky-600 flex items-center justify-center text-white mb-4">
          <Shield className="w-7 h-7" />
        </div>
        <h1 className="text-lg font-semibold text-slate-900 dark:text-white">{t('login.title')}</h1>
        <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">{t('login.subtitle')}</p>

        {status === 'loading' && (
          <p data-testid="login-loading" className="mt-6 text-sm text-slate-500">{t('login.loading')}</p>
        )}
        {status === 'error' && (
          <p data-testid="login-error" className="mt-6 text-sm text-rose-600">{t('login.error', { error })}</p>
        )}
        {(status === 'anonymous' || status === 'error') && (
          <button
            type="button"
            data-testid="login-btn"
            onClick={status === 'error' ? () => window.location.reload() : login}
            className="mt-6 w-full py-2 text-sm font-medium bg-sky-600 hover:bg-sky-700 text-white rounded-lg"
          >
            {status === 'error' ? t('login.retry') : t('login.button')}
          </button>
        )}

        <button
          type="button"
          onClick={toggleLanguage}
          data-testid="login-language-btn"
          className="mt-4 inline-flex items-center gap-1 text-xs text-slate-500 hover:text-slate-700"
        >
          <Globe className="w-3.5 h-3.5" />
          {i18n.language.toUpperCase().slice(0, 2)}
        </button>
      </div>
    </div>
  );
};
