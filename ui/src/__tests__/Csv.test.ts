import { describe, it, expect } from 'vitest';
import { toCsv } from '../lib/csv';

describe('toCsv', () => {
  it('quotes every cell and doubles embedded quotes', () => {
    const out = toCsv(['A', 'B'], [
      ['plain', 'with,comma'],
      ['has "quote"', 42],
    ]);
    expect(out).toBe(
      '"A","B"\r\n"plain","with,comma"\r\n"has ""quote""","42"',
    );
  });

  it('renders only the header for no rows', () => {
    expect(toCsv(['X'], [])).toBe('"X"');
  });
});
