/// <reference types="vite/client" />
import { describe, it, expect } from 'vitest';

// CP-A08: event data (URI, headers, snippets) is attacker-controlled. React
// escapes what it renders; raw HTML would bypass that, and the CSP allows
// no inline script as a second line. No source file may set raw HTML.
const sources = import.meta.glob(['../**/*.{ts,tsx}', '!../**/__tests__/**'], { query: '?raw', import: 'default', eager: true }) as Record<string, string>;

describe('no raw HTML', () => {
  it('scans the sources', () => {
    expect(Object.keys(sources).length).toBeGreaterThan(20);
  });
  it.each(Object.entries(sources))('%s sets no raw HTML', (_name, text) => {
    expect(text).not.toMatch(/dangerouslySetInnerHTML|\.innerHTML\s*=|\.outerHTML\s*=|insertAdjacentHTML|document\.write\(/);
  });
});
