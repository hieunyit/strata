import { act, renderHook, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { useReviewRead } from '../components/policy/useReviewRead';

afterEach(() => { vi.useRealTimers(); vi.restoreAllMocks(); });
it('cancels old versions and ignores stale completion', async () => {
  let finish!: (value: string) => void;
  const read = vi.fn((signal: AbortSignal) => { void signal; return new Promise<string>(resolve => { finish = resolve; }); });
  const view = renderHook(({ key }) => useReviewRead(key, read, 0), { initialProps: { key: 'a:1' } });
  const oldFinish = finish, oldSignal = read.mock.calls[0][0];
  view.rerender({ key: 'b:2' });
  expect(oldSignal.aborted).toBe(true);
  act(() => oldFinish('stale'));
  expect(view.result.current.data).toBeUndefined();
  act(() => finish('current'));
  await waitFor(() => expect(view.result.current.data).toBe('current'));
  const latest = read.mock.calls[1][0]; view.unmount(); expect(latest.aborted).toBe(true);
});
it('never overlaps poll reads and aborts a hung transport at five seconds', async () => {
  vi.useFakeTimers();
  const read = vi.fn((signal: AbortSignal) => new Promise<string>((_, reject) => signal.addEventListener('abort', () => reject(new Error('abort')), { once: true })));
  const view = renderHook(() => useReviewRead('a:1', read, 1000));
  await act(async () => vi.advanceTimersByTime(4000));
  expect(read).toHaveBeenCalledTimes(1);
  await act(async () => vi.advanceTimersByTime(1000));
  expect(view.result.current.error).toBe(true);
  expect(view.result.current.data).toBeUndefined();
  await act(async () => vi.advanceTimersByTime(1000));
  expect(read).toHaveBeenCalledTimes(2);
  view.unmount();
});
it('does not poll a hidden page and loads on return without depending on locale', async () => {
  vi.spyOn(document, 'hidden', 'get').mockReturnValue(true);
  const read = vi.fn().mockResolvedValue('ready');
  const view = renderHook(() => useReviewRead('a:1', read));
  expect(read).not.toHaveBeenCalled();
  vi.spyOn(document, 'hidden', 'get').mockReturnValue(false);
  act(() => document.dispatchEvent(new Event('visibilitychange')));
  await waitFor(() => expect(view.result.current.data).toBe('ready'));
  view.unmount();
});
