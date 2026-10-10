import { useEffect, useState } from 'react';

// Hash routes, so the static build works behind any web server:
//   #/events            #/events/STR-XXXX-...   (opens that decision trace)
//   #/policies          #/fleet
export type Page = 'events' | 'policies' | 'fleet';

export interface Route {
  page: Page;
  blockId?: string;
}

export function parseRoute(hash: string): Route {
  const parts = hash.replace(/^#\/?/, '').split('/').filter(Boolean);
  switch (parts[0]) {
    case 'policies':
      return { page: 'policies' };
    case 'fleet':
      return { page: 'fleet' };
    default:
      return { page: 'events', blockId: parts[0] === 'events' && parts[1] ? decodeURIComponent(parts[1]) : undefined };
  }
}

export function href(route: Route): string {
  if (route.page === 'events' && route.blockId) return `#/events/${encodeURIComponent(route.blockId)}`;
  return `#/${route.page}`;
}

export function navigate(route: Route): void {
  window.location.hash = href(route);
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
