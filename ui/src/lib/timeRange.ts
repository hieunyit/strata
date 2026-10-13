// Time windows offered by the pages: the Overview aggregates over 24 hours,
// 7 or 30 days; the Events search also offers the last 15 minutes and hour.
export type RangeKey = '15m' | '1h' | '24h' | '7d' | '30d';

export const rangeMs: Record<RangeKey, number> = {
  '15m': 15 * 60_000,
  '1h': 60 * 60_000,
  '24h': 24 * 3_600_000,
  '7d': 7 * 24 * 3_600_000,
  '30d': 30 * 24 * 3_600_000,
};

export const overviewRanges: RangeKey[] = ['24h', '7d', '30d'];
export const eventRanges: RangeKey[] = ['15m', '1h', '24h', '7d', '30d'];

export function isRange(v: string | undefined, allowed: RangeKey[]): v is RangeKey {
  return !!v && (allowed as string[]).includes(v);
}

/** the window ending now */
export function windowOf(key: RangeKey, now = new Date()): { from: string; to: string } {
  return { from: new Date(now.getTime() - rangeMs[key]).toISOString(), to: now.toISOString() };
}
