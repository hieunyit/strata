import React, { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { LayoutDashboard, ScrollText, FileCog, Server, Users, History, PanelLeftClose, PanelLeftOpen, X } from 'lucide-react';
import { Header } from './Header';
import { Page, href } from '../../router';
import { readPref, writePref } from '../../lib/prefs';
import { useAuth } from '../../context/AuthContext';

// The mark: three layers of rock in the verdict colors, the same layers
// the overview chart stacks.
export const StrataMark: React.FC<{ className?: string }> = ({ className = 'w-7 h-7' }) => (
  <svg viewBox="0 0 28 28" className={className} aria-hidden>
    <path d="M3 9.5 14 4l11 5.5L14 15z" fill="rgb(var(--other))" />
    <path d="M3 14 14 19.5 25 14v3.5L14 23 3 17.5z" fill="rgb(var(--shadow))" />
    <path d="M3 9.5 14 15l11-5.5V14L14 19.5 3 14z" fill="rgb(var(--block))" />
  </svg>
);

interface NavItem {
  page: Page;
  icon: React.ComponentType<{ className?: string }>;
  /** shown only when this returns true */
  visible?: (roles: string[], localAuth: boolean) => boolean;
}

export const navItems: NavItem[] = [
  { page: 'overview', icon: LayoutDashboard },
  { page: 'events', icon: ScrollText },
  { page: 'policies', icon: FileCog },
  { page: 'fleet', icon: Server },
  // local accounts: admins only, when the control plane has them
  { page: 'users', icon: Users, visible: (roles, localAuth) => localAuth && roles.includes('admin') },
  // audit trail: admins only (audit:read)
  { page: 'audit', icon: History, visible: (roles) => roles.includes('admin') },
];

const Sidebar: React.FC<{ active: Page; collapsed: boolean; onToggle?: () => void; onNavigate?: () => void }> = ({
  active,
  collapsed,
  onToggle,
  onNavigate,
}) => {
  const { t } = useTranslation();
  const { roles, methods } = useAuth();
  const current = active === 'event' ? 'events' : active;
  return (
    <nav aria-label={t('nav.main')} className="flex h-full flex-col bg-rail text-rail-ink select-none border-r border-rail-hover/30">
      <div className={`flex h-14 items-center gap-2.5 border-b border-rail-hover/40 ${collapsed ? 'justify-center' : 'px-4'}`}>
        <div className="p-1 rounded-lg bg-rail-hover/50">
          <StrataMark />
        </div>
        {!collapsed && (
          <div className="leading-tight">
            <div className="text-[15px] font-bold text-white tracking-tight">Strata</div>
            <div className="text-[10px] font-medium tracking-wide text-rail-ink/70 uppercase">{t('app.subtitle')}</div>
          </div>
        )}
      </div>
      <ul className="mt-3 flex-1 space-y-1 px-2.5">
        {navItems
          .filter((n) => !n.visible || n.visible(roles, methods.local))
          .map(({ page, icon: Icon }) => {
            const on = page === current;
            return (
              <li key={page}>
                <a
                  href={href({ page })}
                  onClick={onNavigate}
                  data-testid={`nav-${page}`}
                  aria-current={on ? 'page' : undefined}
                  title={collapsed ? t(`nav.${page}`) : undefined}
                  className={`group relative flex h-9 items-center gap-3 rounded-lg px-2.5 text-[13px] font-medium transition-all ${
                    on ? 'bg-rail-hover text-white shadow-xs' : 'text-rail-ink/80 hover:bg-rail-hover/70 hover:text-white'
                  } ${collapsed ? 'justify-center' : ''}`}
                >
                  {on && (
                    <span className="absolute left-0 top-1.5 bottom-1.5 w-1 rounded-r-full bg-accent shadow-[0_0_8px_rgba(14,124,123,0.8)]" />
                  )}
                  <Icon className={`w-[18px] h-[18px] shrink-0 transition-transform ${on ? 'text-white' : 'text-rail-ink/70 group-hover:text-white group-hover:scale-105'}`} />
                  {!collapsed && <span>{t(`nav.${page}`)}</span>}
                </a>
              </li>
            );
          })}
      </ul>
      {onToggle && (
        <div className="p-2 border-t border-rail-hover/40">
          <button
            type="button"
            onClick={onToggle}
            data-testid="sidebar-toggle"
            aria-label={collapsed ? t('nav.expand') : t('nav.collapse')}
            className={`w-full flex h-8 items-center gap-2.5 rounded-md px-2 text-xs font-medium text-rail-ink/70 hover:bg-rail-hover hover:text-white transition-colors ${collapsed ? 'justify-center' : ''}`}
          >
            {collapsed ? <PanelLeftOpen className="w-4 h-4" /> : <PanelLeftClose className="w-4 h-4" />}
            {!collapsed && <span>{t('nav.collapse')}</span>}
          </button>
        </div>
      )}
    </nav>
  );
};


// AppShell: the left navigation (collapsible, a drawer on small screens),
// the top bar, and the page.
export const AppShell: React.FC<{ active: Page; children: React.ReactNode; wide?: boolean }> = ({ active, children, wide }) => {
  const { t } = useTranslation();
  const [collapsed, setCollapsed] = useState(() => readPref('sidebar') === 'collapsed');
  const [drawer, setDrawer] = useState(false);

  useEffect(() => {
    if (!drawer) return;
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && setDrawer(false);
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [drawer]);

  const toggle = () => {
    writePref('sidebar', collapsed ? 'expanded' : 'collapsed');
    setCollapsed(!collapsed);
  };

  return (
    <div className="min-h-screen bg-paper text-ink">
      <a href="#main" className="sr-only focus:not-sr-only focus:fixed focus:left-2 focus:top-2 focus:z-50 btn">
        {t('nav.skip')}
      </a>
      <aside className={`fixed inset-y-0 left-0 z-40 hidden lg:block transition-[width] ${collapsed ? 'w-16' : 'w-56'}`}>
        <Sidebar active={active} collapsed={collapsed} onToggle={toggle} />
      </aside>
      {drawer && (
        <div className="fixed inset-0 z-50 lg:hidden">
          <div className="absolute inset-0 bg-black/40" onClick={() => setDrawer(false)} />
          <aside className="absolute inset-y-0 left-0 w-64">
            <Sidebar active={active} collapsed={false} onNavigate={() => setDrawer(false)} />
            <button type="button" onClick={() => setDrawer(false)} aria-label={t('common.close')} className="absolute right-2 top-3 p-1.5 text-rail-ink">
              <X className="w-5 h-5" />
            </button>
          </aside>
        </div>
      )}
      <div className={`transition-[padding] ${collapsed ? 'lg:pl-16' : 'lg:pl-56'}`}>
        <Header onOpenMenu={() => setDrawer(true)} />
        <main id="main" className={`mx-auto px-4 py-6 lg:px-8 lg:py-8 ${wide ? 'max-w-[1600px]' : 'max-w-7xl'}`}>
          {children}
        </main>
      </div>
    </div>
  );
};
