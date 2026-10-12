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

  it('neutralizes cells a spreadsheet would run as a formula', () => {
    const out = toCsv(['Path'], [['=HYPERLINK("http://x")'], ['+1'], ['-2'], ['@SUM(A1)'], ['/ok'], [-3]]);
    expect(out.split('\r\n').slice(1)).toEqual([
      '"\'=HYPERLINK(""http://x"")"', '"\'+1"', '"\'-2"', '"\'@SUM(A1)"', '"/ok"', '"-3"',
    ]);
  });

  it('renders only the header for no rows', () => {
    expect(toCsv(['X'], [])).toBe('"X"');
  });
});
