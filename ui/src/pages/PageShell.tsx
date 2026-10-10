import React from 'react';
import { Header } from '../components/layout/Header';
import { Page, navigate } from '../router';

// Pages other than Events: the header's Block ID search opens the trace on
// the Events page.
export const PageShell: React.FC<{ active: Page; children: React.ReactNode }> = ({ active, children }) => (
  <div className="min-h-screen bg-slate-50 dark:bg-slate-950 flex flex-col transition-colors">
    <Header active={active} onSearchBlockId={(id) => navigate({ page: 'events', blockId: id })} />
    <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">{children}</main>
  </div>
);

export const ErrorBanner: React.FC<{ message?: string }> = ({ message }) =>
  message ? (
    <div data-testid="page-error" className="mb-4 p-3 rounded-lg bg-rose-50 dark:bg-rose-950/40 border border-rose-200 dark:border-rose-900 text-sm text-rose-700 dark:text-rose-300">
      {message}
    </div>
  ) : null;

export function formatTime(iso: string | undefined, locale: string, never: string): string {
  if (!iso) return never;
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString(locale);
}
