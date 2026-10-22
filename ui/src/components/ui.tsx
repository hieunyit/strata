import React from 'react';
import { useTranslation } from 'react-i18next';
import { AlertCircle, ShieldX, Eye, CheckCircle, AlertTriangle } from 'lucide-react';
import { RangeKey } from '../lib/timeRange';

// Small shared pieces of the console: verdict badges, the time range
// switch, page headers and empty or failed states.

export type Verdict = 'block' | 'shadow' | 'pass' | 'error';

export function verdictOf(action: string | undefined): Verdict {
  const a = (action ?? '').toLowerCase();
  return a === 'block' || a === 'shadow' || a === 'error' ? a : 'pass';
}

const verdictClass: Record<Verdict, string> = {
  block: 'text-block bg-block/10 border-block/40 border-solid',
  shadow: 'text-shadow bg-shadow/10 border-shadow/40 border-dashed',
  pass: 'text-other bg-other/10 border-other/30 border-dotted',
  error: 'text-muted bg-sunken border-line',
};

const verdictIcon: Record<Verdict, React.ComponentType<{ className?: string }>> = {
  block: ShieldX,
  shadow: Eye,
  pass: CheckCircle,
  error: AlertTriangle,
};

export const VerdictBadge: React.FC<{ action?: string; size?: 'sm' | 'md' }> = ({ action, size = 'sm' }) => {
  const { t } = useTranslation();
  const v = verdictOf(action);
  const Icon = verdictIcon[v];
  const iconSize = size === 'md' ? 'w-3.5 h-3.5' : 'w-3 h-3';
  return (
    <span
      data-testid="verdict"
      data-verdict={v}
      className={`inline-flex items-center gap-1.5 rounded border font-medium whitespace-nowrap ${verdictClass[v]} ${
        size === 'md' ? 'px-2.5 py-1 text-[13px]' : 'px-1.5 py-0.5 text-xs'
      }`}
    >
      <Icon className={`${iconSize} shrink-0`} aria-hidden />
      {t(`verdict.${v}`)}
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
    <div role="radiogroup" aria-label={t('range.label')} data-testid={testId} className="inline-flex rounded border border-line bg-surface p-0.5">
      {options.map((o) => (
        <button
          key={o}
          type="button"
          role="radio"
          aria-checked={o === value}
          data-testid={`range-${o}`}
          onClick={() => onChange(o)}
          className={`h-7 px-3 rounded-sm text-[13px] transition-colors ${
            o === value ? 'bg-ink text-paper font-medium' : 'text-muted hover:text-ink'
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
        <h1 className="text-[22px] leading-tight font-semibold text-ink">{title}</h1>
        {description && <p className="mt-1 text-[13px] text-muted max-w-[70ch]">{description}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
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
    <div data-testid={testId} role="alert" className="mb-4 flex items-start gap-2.5 rounded-md border border-block/30 bg-block/5 px-3 py-2.5 text-[13px] text-ink">
      <AlertCircle className="mt-0.5 w-4 h-4 shrink-0 text-block" />
      <span className="flex-1">{message}</span>
      {onClose && (
        <button type="button" onClick={onClose} className="text-xs text-muted hover:text-ink">
          {t('common.dismiss')}
        </button>
      )}
    </div>
  );
};

export const SectionTitle: React.FC<{ children: React.ReactNode; aside?: React.ReactNode }> = ({ children, aside }) => (
  <div className="flex items-baseline justify-between gap-3 px-4 pt-3.5 pb-2.5 border-b border-line">
    <h2 className="text-[13px] font-semibold text-ink">{children}</h2>
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

/** 2147483648 -> "2 GiB"; values the API sends as a count of bytes. */
export function formatBytes(n: number | string | undefined, locale: string): string {
  const v = typeof n === 'string' ? Number(n) : n;
  if (v === undefined || !Number.isFinite(v)) return '—';
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let x = v;
  let i = 0;
  while (Math.abs(x) >= 1024 && i < units.length - 1) {
    x /= 1024;
    i++;
  }
  return `${new Intl.NumberFormat(locale, { maximumFractionDigits: i === 0 ? 0 : 1 }).format(x)} ${units[i]}`;
}

/** "lab-operator (oidc:8e1c…)" -> "lab-operator": the name a record was
 * made by, without its subject (shown in full as a tooltip). */
export function actorName(actor: string | undefined): string {
  if (!actor) return '';
  const i = actor.indexOf(' (');
  return i > 0 && actor.endsWith(')') ? actor.slice(0, i) : actor;
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
