import { useEffect, useState } from 'react';

// Hash routes, so the static build works behind any web server:
//   #/overview?range=7d
//   #/map?range=24h&country=VN       the attack map (W18-F-01)
//   #/events?range=24h&action=block&rule_id=942100
//   #/events/STR-XXXX-...          the decision trace of one event
//   #/policies   #/fleet   #/users
export type Page = 'releases' | 'applications' | 'overview' | 'map' | 'events' | 'event' | 'policies' | 'fleet' | 'users' | 'audit' | 'reviews';

export interface Route {
  page: Page;
  blockId?: string;
  /** query parameters of the hash (filters, time range) */
  query?: Record<string, string>;
}

const simple: Page[] = ['releases', 'applications', 'overview', 'map', 'events', 'policies', 'fleet', 'users', 'audit', 'reviews'];

export function parseRoute(hash: string): Route {
  const raw = hash.replace(/^#\/?/, '');
  const [pathPart, queryPart] = raw.split('?', 2);
  const parts = pathPart.split('/').filter(Boolean);
  const query: Record<string, string> = {};
  if (queryPart) {
    new URLSearchParams(queryPart).forEach((v, k) => {
      query[k] = v;
    });
  }
  const withQuery = (r: Route): Route => (Object.keys(query).length ? { ...r, query } : r);
  if (parts[0] === 'events' && parts[1]) {
    return { page: 'event', blockId: decodeURIComponent(parts[1]) };
  }
  if (simple.includes(parts[0] as Page)) {
    return withQuery({ page: parts[0] as Page });
  }
  return withQuery({ page: 'overview' });
}

export function href(route: Route): string {
  if (route.page === 'event' && route.blockId) return `#/events/${encodeURIComponent(route.blockId)}`;
  const page = route.page === 'event' ? 'events' : route.page;
  const q = route.query ? new URLSearchParams(Object.entries(route.query).filter(([, v]) => v !== '')).toString() : '';
  return `#/${page}${q ? `?${q}` : ''}`;
}

export function navigate(route: Route): void {
  window.location.hash = href(route);
}

// replaceQuery updates the current page's query without a history entry
// (filters typed on a page should not fill the back button).
export function replaceQuery(route: Route): void {
  window.history.replaceState(null, '', href(route));
}

export function useRoute(): Route {
  const [route, setRoute] = useState<Route>(() => parseRoute(window.location.hash));
  useEffect(() => {
    const on = () => setRoute(parseRoute(window.location.hash));
    window.addEventListener('hashchange', on);
    return () => window.removeEventListener('hashchange', on);
  }, []);
  return route;
}
