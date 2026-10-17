import React, { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Search, Moon, Sun, LogOut, Menu, Languages, KeyRound } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { apiClient } from '../../api/client';
import { navigate } from '../../router';
import { useTheme } from '../../lib/theme';
import { ChangePasswordDialog } from './ChangePasswordDialog';

interface HeaderProps {
  /** default: open the event's page */
  onSearchBlockId?: (blockId: string) => void;
  onOpenMenu?: () => void;
}

const BLOCK_ID = /^(STR|EVT)-[0-9A-Z]{4}(-[0-9A-Z]{4}){3}$/;

// The top bar: the Block ID lookup, the helpdesk's first move, is always
// here; then the console's version, language, theme and the session.
export const Header: React.FC<HeaderProps> = ({ onSearchBlockId, onOpenMenu }) => {
  const { t, i18n } = useTranslation();
  const { role, username, logout, isLocal } = useAuth();
  const [pwOpen, setPwOpen] = useState(false);
  const [theme, toggleTheme] = useTheme();
  const [version, setVersion] = useState('');
  const [input, setInput] = useState('');
  const [error, setError] = useState('');

  useEffect(() => {
    let alive = true;
    apiClient
      .getVersion()
      .then((v) => alive && setVersion(v.version ?? ''))
      .catch(() => {});
    return () => {
      alive = false;
    };
  }, []);

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    const id = input.trim().toUpperCase();
    if (!id) return;
    if (!id.startsWith('STR-') && !id.startsWith('EVT-')) {
      setError(t('header.blockIdPrefix'));
      return;
    }
    if (!BLOCK_ID.test(id)) {
      setError(t('header.blockIdFormat'));
      return;
    }
    setError('');
    setInput('');
    (onSearchBlockId ?? ((b: string) => navigate({ page: 'event', blockId: b })))(id);
  };

  const lang = i18n.language.startsWith('vi') ? 'vi' : 'en';

  return (
    <header className="sticky top-0 z-30 h-14 bg-surface/95 backdrop-blur border-b border-line flex items-center gap-3 px-4 lg:px-6">
      <button type="button" onClick={onOpenMenu} aria-label={t('nav.menu')} className="lg:hidden p-1.5 -ml-1.5 rounded text-muted hover:text-ink">
        <Menu className="w-5 h-5" />
      </button>

      <form onSubmit={submit} className="relative flex-1 max-w-lg" data-testid="block-id-search-form" role="search">
        <label htmlFor="block-id-search" className="sr-only">
          {t('header.searchLabel')}
        </label>
        <div className="relative flex items-center">
          <Search className="w-4 h-4 text-faint absolute left-3 pointer-events-none" aria-hidden />
          <input
            id="block-id-search"
            data-testid="block-id-search-input"
            value={input}
            onChange={(e) => {
              setInput(e.target.value);
              if (error) setError('');
            }}
            placeholder={t('header.searchPlaceholder')}
            spellCheck={false}
            autoComplete="off"
            className="field h-9 pl-9 pr-20 font-mono text-[13px] uppercase placeholder:normal-case placeholder:font-sans bg-sunken/40 focus:bg-surface border-line/80 focus:border-accent shadow-xs"
            aria-invalid={!!error}
            aria-describedby={error ? 'block-id-error' : undefined}
          />
          <kbd className="absolute right-16 hidden sm:inline-flex items-center h-5 px-1.5 text-[10px] font-mono font-medium text-faint bg-sunken rounded border border-line pointer-events-none">
            /
          </kbd>
          <button
            type="submit"
            data-testid="block-id-search-btn"
            disabled={!input.trim()}
            className="absolute right-1.5 h-6 px-2.5 rounded text-xs font-medium bg-accent text-accent-ink hover:opacity-90 disabled:opacity-40 transition-all shadow-xs"
          >
            {t('header.searchBtn')}
          </button>
        </div>
        {error && (
          <div id="block-id-error" role="alert" className="absolute top-full left-0 mt-1.5 z-50 rounded-md border border-block/30 bg-surface px-2.5 py-1 text-xs text-block shadow-md">
            {error}
          </div>
        )}
      </form>

      <div className="hidden lg:flex items-center gap-2 px-2.5 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs font-mono shadow-xs">
        <span className="relative flex h-2 w-2">
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
          <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
        </span>
        <span className="font-semibold tracking-wider text-[11px] uppercase">Enforcing</span>
      </div>

      <div className="ml-auto flex items-center gap-1.5">
        {version && (
          <span data-testid="cp-version" className="hidden xl:inline mr-2 px-2 py-0.5 rounded text-[11px] font-mono text-faint bg-sunken/60 border border-line/60">
            {t('header.version', { version })}
          </span>
        )}
        <button
          type="button"
          onClick={() => void i18n.changeLanguage(lang === 'en' ? 'vi' : 'en')}
          data-testid="language-toggle-btn"
          title={t('header.lang')}
          aria-label={t('header.lang')}
          className="h-8 px-2.5 inline-flex items-center gap-1 rounded-md text-xs font-semibold text-muted hover:text-ink hover:bg-sunken border border-transparent hover:border-line transition-all"
        >
          <Languages className="w-3.5 h-3.5" />
          {lang.toUpperCase()}
        </button>
        <button
          type="button"
          onClick={toggleTheme}
          data-testid="theme-toggle-btn"
          title={t('header.theme')}
          aria-label={t('header.theme')}
          className="h-8 w-8 inline-flex items-center justify-center rounded-md text-muted hover:text-ink hover:bg-sunken border border-transparent hover:border-line transition-all"
        >
          {theme === 'dark' ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
        </button>
        <div className="mx-1 h-5 w-px bg-line/80 hidden sm:block" />
        <div data-testid="current-user" title={t('header.signedInAs', { name: username ?? '' })} className="hidden sm:flex items-center gap-2 pl-2 pr-2.5 py-1 rounded-full border border-line bg-surface shadow-xs mr-0.5">
          <div className="w-5 h-5 rounded-full bg-accent/15 text-accent flex items-center justify-center font-bold text-[11px] uppercase shrink-0" aria-hidden>
            {username ? username[0] : 'U'}
          </div>
          <div className="flex flex-col items-start leading-none pr-0.5">
            <span className="text-[12px] font-semibold text-ink max-w-[12ch] truncate">{username}</span>
            <span data-testid="current-role" className="text-[10px] text-muted capitalize mt-0.5">
              {t(`header.roles.${role ?? 'none'}`)}
            </span>
          </div>
        </div>
        {isLocal && (
          <button
            type="button"
            onClick={() => setPwOpen(true)}
            data-testid="change-password-open"
            title={t('account.title')}
            aria-label={t('account.title')}
            className="h-8 w-8 inline-flex items-center justify-center rounded-md text-muted hover:text-ink hover:bg-sunken transition-colors"
          >
            <KeyRound className="w-4 h-4" />
          </button>
        )}
        <button
          type="button"
          onClick={logout}
          data-testid="logout-btn"
          title={t('header.logout')}
          aria-label={t('header.logout')}
          className="h-8 w-8 inline-flex items-center justify-center rounded-md text-muted hover:text-ink hover:bg-sunken transition-colors"
        >
          <LogOut className="w-4 h-4" />
        </button>
      </div>
      {pwOpen && <ChangePasswordDialog onClose={() => setPwOpen(false)} />}
    </header>
  );
};
