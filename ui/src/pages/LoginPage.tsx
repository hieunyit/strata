import React from 'react';
import { useTranslation } from 'react-i18next';
import { Languages } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { StrataMark } from '../components/layout/AppShell';

// Shown until the user has a session; signing in redirects to the OIDC
// provider (authorization code with PKCE).
export const LoginPage: React.FC = () => {
  const { t, i18n } = useTranslation();
  const { status, error, login } = useAuth();
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
          <p className="mt-1 text-[13px] text-muted">{t('login.subtitle')}</p>

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
          {(status === 'anonymous' || status === 'error') && (
            <button
              type="button"
              data-testid="login-btn"
              onClick={status === 'error' ? () => window.location.reload() : login}
              className="btn-primary mt-6 h-10 w-full text-sm"
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
