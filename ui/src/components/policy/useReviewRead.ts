import { useCallback, useEffect, useRef, useState } from 'react';

// One bounded read at a time, only while visible. No result survives a
// resource-key change, even when an old transport ignores cancellation.
export function useReviewRead<T>(key: string, load: (signal: AbortSignal) => Promise<T>, interval = 15000) {
  const loader = useRef(load); loader.current = load;
  const [revision, setRevision] = useState(0);
  const [state, setState] = useState<{ key: string; data?: T; loading: boolean; error: boolean }>({ key, loading: true, error: false });
  const refresh = useCallback(() => setRevision(n => n + 1), []);
  useEffect(() => {
    let active = true, busy = false;
    let next: ReturnType<typeof setTimeout> | undefined;
    let controller: AbortController | undefined;
    const read = async () => {
      if (!active || busy || document.hidden) return;
      clearTimeout(next); busy = true;
      controller = new AbortController();
      const current = controller;
      setState(s => ({ key, data: s.key === key ? s.data : undefined, loading: true, error: false }));
      const timeout = setTimeout(() => current.abort(), 5000);
      try {
        const data = await loader.current(current.signal);
        if (active && !current.signal.aborted) setState({ key, data, loading: false, error: false });
        else if (active) setState(s => ({ key, data: s.key === key ? s.data : undefined, loading: false, error: true }));
      } catch {
        if (active) setState(s => ({ key, data: s.key === key ? s.data : undefined, loading: false, error: true }));
      } finally {
        clearTimeout(timeout); busy = false;
        if (active && interval > 0) next = setTimeout(() => void read(), interval);
      }
    };
    setState({ key, loading: true, error: false });
    void read();
    const visibility = () => { if (!document.hidden) void read(); };
    document.addEventListener('visibilitychange', visibility);
    return () => { active = false; clearTimeout(next); controller?.abort(); document.removeEventListener('visibilitychange', visibility); };
  }, [key, revision, interval]);
  return { ...(state.key === key ? state : { loading: true, error: false, data: undefined }), refresh };
}
