// Per-browser preferences (language, theme, sidebar). Storage may be
// unavailable (private windows, blocked site data): the UI then simply
// starts with the defaults.
const prefix = 'strata.';

export function readPref(key: string): string | null {
  try {
    return window.localStorage.getItem(prefix + key);
  } catch {
    return null;
  }
}

export function writePref(key: string, value: string): void {
  try {
    window.localStorage.setItem(prefix + key, value);
  } catch {
    // not remembered; nothing else depends on it
  }
}
