import React, { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Shield, Search, Globe, UserCheck, Moon, Sun, AlertCircle, LogOut } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { apiClient } from '../../api/client';
import { Page, href } from '../../router';

interface HeaderProps {
  onSearchBlockId: (blockId: string) => void;
  isSearchingBlockId?: boolean;
  active?: Page;
}

const pages: Page[] = ['events', 'policies', 'fleet'];

export const Header: React.FC<HeaderProps> = ({ onSearchBlockId, isSearchingBlockId = false, active = 'events' }) => {
  const { t, i18n } = useTranslation();
  const { role, username, logout } = useAuth();
  const [version, setVersion] = useState<string>('');
  const [searchInput, setSearchInput] = useState('');
  const [isDarkMode, setIsDarkMode] = useState(false);
  const [searchError, setSearchError] = useState('');

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

  const toggleLanguage = () => {
    const nextLang = i18n.language.startsWith('vi') ? 'en' : 'vi';
    i18n.changeLanguage(nextLang);
  };

  const toggleTheme = () => {
    const nextMode = !isDarkMode;
    setIsDarkMode(nextMode);
    if (nextMode) {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
  };

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setSearchError('');
    const trimmed = searchInput.trim().toUpperCase();
    if (!trimmed) return;

    // Check basic format
    if (!trimmed.startsWith('STR-') && !trimmed.startsWith('EVT-')) {
      setSearchError(t('header.blockIdPrefix'));
      return;
    }

    onSearchBlockId(trimmed);
  };

  return (
    <header className="sticky top-0 z-30 bg-white/95 dark:bg-slate-900/95 backdrop-blur border-b border-slate-200 dark:border-slate-800 transition-colors">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between gap-4">
        {/* Brand */}
        <div className="flex items-center gap-3 shrink-0">
          <div className="w-10 h-10 rounded-lg bg-sky-600 flex items-center justify-center text-white shadow-md shadow-sky-600/20">
            <Shield className="w-6 h-6" />
          </div>
          <div>
            <div className="font-bold text-lg leading-tight tracking-tight text-slate-900 dark:text-white flex items-center gap-1.5">
              <span>Strata</span>
              <span className="text-xs uppercase px-1.5 py-0.5 rounded bg-sky-100 text-sky-800 dark:bg-sky-950 dark:text-sky-300 font-semibold">
                WAF
              </span>
            </div>
            <div className="text-xs text-slate-500 dark:text-slate-400">
              {t('app.subtitle')}
            </div>
          </div>
        </div>

        {/* Global Block ID Search */}
        <div className="flex-1 max-w-xl">
          <form onSubmit={handleSearchSubmit} className="relative" data-testid="block-id-search-form">
            <div className="relative">
              <input
                type="text"
                data-testid="block-id-search-input"
                value={searchInput}
                onChange={(e) => {
                  setSearchInput(e.target.value);
                  if (searchError) setSearchError('');
                }}
                placeholder={t('header.searchPlaceholder')}
                className="w-full pl-10 pr-24 py-2 text-sm bg-slate-100 dark:bg-slate-800/80 border border-slate-200 dark:border-slate-700 rounded-lg focus:outline-none focus:ring-2 focus:ring-sky-500 dark:text-white transition-all shadow-inner"
              />
              <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-3" />
              <button
                type="submit"
                data-testid="block-id-search-btn"
                disabled={isSearchingBlockId || !searchInput.trim()}
                className="absolute right-1.5 top-1.5 px-3 py-1 text-xs font-medium bg-sky-600 hover:bg-sky-700 disabled:opacity-50 text-white rounded transition-colors shadow-sm"
              >
                {isSearchingBlockId ? '...' : t('header.searchBtn')}
              </button>
            </div>
            {searchError && (
              <div className="absolute top-full left-0 mt-1 text-xs text-rose-500 flex items-center gap-1 bg-white dark:bg-slate-900 p-1 rounded shadow">
                <AlertCircle className="w-3 h-3" />
                <span>{searchError}</span>
              </div>
            )}
          </form>
        </div>

        {/* Right Controls */}
        <div className="flex items-center gap-2 shrink-0">
          {/* Signed-in user; the role comes from the access token */}
          <div
            data-testid="current-user"
            title={t('header.signedInAs', { name: username ?? '' })}
            className="hidden md:flex items-center gap-1.5 bg-slate-100 dark:bg-slate-800 px-2.5 py-1.5 rounded-lg border border-slate-200 dark:border-slate-700 text-xs text-slate-700 dark:text-slate-200"
          >
            <UserCheck className="w-3.5 h-3.5 text-slate-500 dark:text-slate-400" />
            <span className="font-medium">{username}</span>
            <span data-testid="current-role" className="text-slate-500 dark:text-slate-400">
              {t(`header.roles.${role ?? 'none'}`)}
            </span>
          </div>

          {version && (
            <span data-testid="cp-version" className="hidden lg:inline text-[11px] text-slate-400">
              {t('header.version', { version })}
            </span>
          )}

          {/* Language Switch */}
          <button
            onClick={toggleLanguage}
            data-testid="language-toggle-btn"
            title={t('header.lang')}
            className="flex items-center gap-1 px-2.5 py-1.5 text-xs font-semibold bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 rounded-lg border border-slate-200 dark:border-slate-700 transition-colors"
          >
            <Globe className="w-3.5 h-3.5" />
            <span>{i18n.language.toUpperCase().slice(0, 2)}</span>
          </button>

          {/* Theme Toggle */}
          <button
            onClick={toggleTheme}
            data-testid="theme-toggle-btn"
            title={t('header.theme')}
            className="p-2 text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200 bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 rounded-lg border border-slate-200 dark:border-slate-700 transition-colors"
          >
            {isDarkMode ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
          </button>

          <button
            onClick={logout}
            data-testid="logout-btn"
            title={t('header.logout')}
            className="p-2 text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200 bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 rounded-lg border border-slate-200 dark:border-slate-700 transition-colors"
          >
            <LogOut className="w-4 h-4" />
          </button>
        </div>
      </div>
      <nav className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex gap-1 text-sm" aria-label="main">
        {pages.map((p) => (
          <a
            key={p}
            href={href({ page: p })}
            data-testid={`nav-${p}`}
            aria-current={p === active ? 'page' : undefined}
            className={
              p === active
                ? 'px-3 py-2 border-b-2 border-sky-600 text-sky-700 dark:text-sky-300 font-medium'
                : 'px-3 py-2 border-b-2 border-transparent text-slate-500 hover:text-slate-800 dark:hover:text-slate-200'
            }
          >
            {t(`nav.${p}`)}
          </a>
        ))}
      </nav>
    </header>
  );
};
