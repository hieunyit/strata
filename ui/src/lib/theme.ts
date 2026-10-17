import { useEffect, useState } from 'react';
import { readPref, writePref } from './prefs';

export type Theme = 'light' | 'dark';

function initial(): Theme {
  const saved = readPref('theme');
  if (saved === 'light' || saved === 'dark') return saved;
  return 'dark';
}

function apply(theme: Theme): void {
  document.documentElement.classList.toggle('dark', theme === 'dark');
  window.dispatchEvent(new CustomEvent('strata-theme', { detail: theme }));
}

// applyInitialTheme runs before the first render, so the page does not
// flash light before turning dark.
export function applyInitialTheme(): void {
  apply(initial());
}

export function useTheme(): [Theme, () => void] {
  const [theme, setTheme] = useState<Theme>(() =>
    document.documentElement.classList.contains('dark') ? 'dark' : 'light',
  );
  useEffect(() => {
    const on = (e: Event) => setTheme((e as CustomEvent<Theme>).detail);
    window.addEventListener('strata-theme', on);
    return () => window.removeEventListener('strata-theme', on);
  }, []);
  const toggle = () => {
    const next: Theme = theme === 'dark' ? 'light' : 'dark';
    writePref('theme', next);
    apply(next);
  };
  return [theme, toggle];
}
