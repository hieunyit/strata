import React from 'react';
import { useTranslation } from 'react-i18next';
import { AlertCircle } from 'lucide-react';
import { RangeKey } from '../lib/timeRange';

// Small shared pieces of the console: verdict badges, the time range
// switch, page headers and empty or failed states.

export type Verdict = 'block' | 'shadow' | 'pass' | 'error';

export function verdictOf(action: string | undefined): Verdict {
  const a = (action ?? '').toLowerCase();
  return a === 'block' || a === 'shadow' || a === 'error' ? a : 'pass';
}

const verdictClass: Record<Verdict, string> = {
  block: 'text-block bg-block/10 border-block/30',
  shadow: 'text-shadow bg-shadow/10 border-shadow/35',
  pass: 'text-other bg-other/10 border-other/30',
  error: 'text-muted bg-sunken border-line',
};

const verdictDot: Record<Verdict, string> = {
  block: 'bg-block',
  shadow: 'bg-shadow',
  pass: 'bg-other',
  error: 'bg-faint',
};

export const VerdictBadge: React.FC<{ action?: string; size?: 'sm' | 'md' }> = ({ action, size = 'sm' }) => {
  const { t } = useTranslation();
  const v = verdictOf(action);
  return (
    <span
      data-testid="verdict"
      data-verdict={v}
      className={`inline-flex items-center gap-1.5 rounded-full border font-medium whitespace-nowrap shadow-xs ${verdictClass[v]} ${
        size === 'md' ? 'px-3 py-1 text-[13px]' : 'px-2 py-0.5 text-xs'
      }`}
    >
      <span className={`w-1.5 h-1.5 rounded-full ${verdictDot[v]} ${v === 'block' ? 'animate-pulse' : ''}`} />
      {t(`verdict.${v}`)}
    </span>
  );
};

export const MethodBadge: React.FC<{ method?: string }> = ({ method }) => {
  const m = (method ?? 'GET').toUpperCase();
  const styles: Record<string, string> = {
    GET: 'text-sky-700 bg-sky-50 dark:text-sky-300 dark:bg-sky-950/40 border-sky-200 dark:border-sky-800/60',
    POST: 'text-emerald-700 bg-emerald-50 dark:text-emerald-300 dark:bg-emerald-950/40 border-emerald-200 dark:border-emerald-800/60',
    PUT: 'text-amber-700 bg-amber-50 dark:text-amber-300 dark:bg-amber-950/40 border-amber-200 dark:border-amber-800/60',
    PATCH: 'text-amber-700 bg-amber-50 dark:text-amber-300 dark:bg-amber-950/40 border-amber-200 dark:border-amber-800/60',
    DELETE: 'text-rose-700 bg-rose-50 dark:text-rose-300 dark:bg-rose-950/40 border-rose-200 dark:border-rose-800/60',
    HEAD: 'text-purple-700 bg-purple-50 dark:text-purple-300 dark:bg-purple-950/40 border-purple-200 dark:border-purple-800/60',
    OPTIONS: 'text-slate-700 bg-slate-50 dark:text-slate-300 dark:bg-slate-800/40 border-slate-200 dark:border-slate-700/60',
  };
  return (
    <span className={`inline-flex items-center justify-center font-mono text-[11px] font-semibold px-1.5 py-0.5 rounded border ${styles[m] ?? 'text-muted bg-sunken border-line'}`}>
      {m}
    </span>
  );
};

export const RangeSwitch: React.FC<{
  value: RangeKey;
  options: RangeKey[];
  onChange: (r: RangeKey) => void;
  testId?: string;
}> = ({ value, options, onChange, testId = 'range-switch' }) => {
  const { t } = useTranslation();
  return (
    <div role="radiogroup" aria-label={t('range.label')} data-testid={testId} className="inline-flex rounded-lg border border-line bg-surface p-0.5 shadow-xs">
      {options.map((o) => (
        <button
          key={o}
          type="button"
          role="radio"
          aria-checked={o === value}
          data-testid={`range-${o}`}
          onClick={() => onChange(o)}
          className={`h-7 px-3 rounded-md text-[13px] transition-all ${
            o === value ? 'bg-ink text-paper font-medium shadow-xs' : 'text-muted hover:text-ink hover:bg-sunken/60'
          }`}
        >
          {t(`range.${o}`)}
        </button>
      ))}
    </div>
  );
};

export const PageHeader: React.FC<{ title: string; description?: string; actions?: React.ReactNode; back?: React.ReactNode }> = ({
  title,
  description,
  actions,
  back,
}) => (
  <div className="mb-6">
    {back}
    <div className="flex flex-wrap items-end justify-between gap-4">
      <div className="min-w-0">
        <h1 className="text-[24px] leading-tight font-bold tracking-tight text-ink">{title}</h1>
        {description && <p className="mt-1 text-[13px] text-muted max-w-[70ch] leading-relaxed">{description}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2.5">{actions}</div>}
    </div>
  </div>
);

export const ErrorBanner: React.FC<{ message?: string | null; onClose?: () => void; testId?: string }> = ({
  message,
  onClose,
  testId = 'page-error',
}) => {
  const { t } = useTranslation();
  if (!message) return null;
  return (
    <div data-testid={testId} role="alert" className="mb-5 flex items-start gap-2.5 rounded-lg border border-block/30 bg-block/5 px-4 py-3 text-[13px] text-ink shadow-xs">
      <AlertCircle className="mt-0.5 w-4 h-4 shrink-0 text-block" />
      <span className="flex-1">{message}</span>
      {onClose && (
        <button type="button" onClick={onClose} className="text-xs font-medium text-muted hover:text-ink">
          {t('common.dismiss')}
        </button>
      )}
    </div>
  );
};

export const SectionTitle: React.FC<{ children: React.ReactNode; aside?: React.ReactNode }> = ({ children, aside }) => (
  <div className="flex items-center justify-between gap-3 px-5 py-3.5 border-b border-line">
    <h2 className="text-[14px] font-semibold text-ink tracking-tight">{children}</h2>
    {aside && <div className="text-xs text-muted">{aside}</div>}
  </div>
);


export const Empty: React.FC<{ children: React.ReactNode; testId?: string }> = ({ children, testId }) => (
  <div data-testid={testId} className="px-4 py-8 text-center text-[13px] text-muted">
    {children}
  </div>
);

export function formatCount(n: number | undefined, locale: string): string {
  return new Intl.NumberFormat(locale).format(n ?? 0);
}

export function formatTime(iso: string | undefined, locale: string, never: string): string {
  if (!iso) return never;
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString(locale);
}

/** "3 min ago", "2 h ago", or the date beyond a week */
export function relativeTime(iso: string | undefined, locale: string, now = Date.now()): string {
  if (!iso) return '';
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return iso;
  const s = Math.round((t - now) / 1000);
  const rtf = new Intl.RelativeTimeFormat(locale, { numeric: 'auto' });
  const abs = Math.abs(s);
  if (abs < 60) return rtf.format(s, 'second');
  if (abs < 3600) return rtf.format(Math.round(s / 60), 'minute');
  if (abs < 86400) return rtf.format(Math.round(s / 3600), 'hour');
  if (abs < 7 * 86400) return rtf.format(Math.round(s / 86400), 'day');
  return new Date(t).toLocaleDateString(locale);
}
