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
        <Search className="w-4 h-4 text-faint absolute left-2.5 top-2" aria-hidden />
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
          className="field pl-8 pr-20 font-mono text-[13px] uppercase placeholder:normal-case placeholder:font-sans"
          aria-invalid={!!error}
          aria-describedby={error ? 'block-id-error' : undefined}
        />
        <button
          type="submit"
          data-testid="block-id-search-btn"
          disabled={!input.trim()}
          className="absolute right-1 top-1 h-6 px-2.5 rounded-sm text-xs font-medium bg-accent text-accent-ink disabled:opacity-40"
        >
          {t('header.searchBtn')}
        </button>
        {error && (
          <div id="block-id-error" role="alert" className="absolute top-full left-0 mt-1 rounded border border-block/30 bg-surface px-2 py-1 text-xs text-block shadow-sm">
            {error}
          </div>
        )}
      </form>

      <div className="ml-auto flex items-center gap-1">
        {version && (
          <span data-testid="cp-version" className="hidden xl:inline mr-2 text-xs text-faint">
            {t('header.version', { version })}
          </span>
        )}
        <button
          type="button"
          onClick={() => void i18n.changeLanguage(lang === 'en' ? 'vi' : 'en')}
          data-testid="language-toggle-btn"
          title={t('header.lang')}
          aria-label={t('header.lang')}
          className="h-8 px-2 inline-flex items-center gap-1 rounded text-xs font-medium text-muted hover:text-ink hover:bg-sunken"
        >
          <Languages className="w-4 h-4" />
          {lang.toUpperCase()}
        </button>
        <button
          type="button"
          onClick={toggleTheme}
          data-testid="theme-toggle-btn"
          title={t('header.theme')}
          aria-label={t('header.theme')}
          className="h-8 w-8 inline-flex items-center justify-center rounded text-muted hover:text-ink hover:bg-sunken"
        >
          {theme === 'dark' ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
        </button>
        <div className="mx-2 h-6 w-px bg-line hidden sm:block" />
        <div data-testid="current-user" title={t('header.signedInAs', { name: username ?? '' })} className="hidden sm:flex flex-col items-end leading-tight mr-1">
          <span className="text-[13px] font-medium text-ink max-w-[14ch] truncate">{username}</span>
          <span data-testid="current-role" className="text-[11px] text-muted">
            {t(`header.roles.${role ?? 'none'}`)}
          </span>
        </div>
        {isLocal && (
          <button
            type="button"
            onClick={() => setPwOpen(true)}
            data-testid="change-password-open"
            title={t('account.title')}
            aria-label={t('account.title')}
            className="h-8 w-8 inline-flex items-center justify-center rounded text-muted hover:text-ink hover:bg-sunken"
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
          className="h-8 w-8 inline-flex items-center justify-center rounded text-muted hover:text-ink hover:bg-sunken"
        >
          <LogOut className="w-4 h-4" />
        </button>
      </div>
      {pwOpen && <ChangePasswordDialog onClose={() => setPwOpen(false)} />}
    </header>
  );
};
