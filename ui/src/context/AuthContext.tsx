import React, { createContext, useContext, useEffect, useMemo, useState } from 'react';
import { UserManager, WebStorageStateStore, User } from 'oidc-client-ts';
import { loadConfig } from '../auth/config';
import { UserRole, rolesFromAccessToken, primaryRole } from '../auth/roles';
import { setAuthHandlers } from '../api/client';

export type { UserRole } from '../auth/roles';

export type AuthStatus = 'loading' | 'anonymous' | 'authenticated' | 'error';

interface AuthContextType {
  status: AuthStatus;
  error?: string;
  username?: string;
  roles: UserRole[];
  role?: UserRole;
  // No role that may see full client IPs and input snippets.
  isViewer: boolean;
  login: () => void;
  logout: () => void;
  maskIp: (ip: string) => string;
  maskSnippet: (snippet: string) => string;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

// The API masks for viewers already; this only keeps the screen consistent
// if a cached response is shown after a role change.
function makeMasks(isViewer: boolean) {
  const maskIp = (ip: string): string => {
    if (!isViewer || !ip) return ip;
    if (ip.endsWith('/24') || ip.endsWith('/48') || ip === '[REDACTED]') return ip;
    if (ip.includes('.')) {
      const parts = ip.split('.');
      if (parts.length === 4) return `${parts[0]}.${parts[1]}.***.***`;
    } else if (ip.includes(':')) {
      const parts = ip.split(':');
      if (parts.length > 2) return `${parts[0]}:${parts[1]}:****:****`;
    }
    return '***.***.***.***';
  };
  const maskSnippet = (snippet: string): string => (isViewer ? '[REDACTED FOR VIEWER ROLE]' : snippet);
  return { maskIp, maskSnippet };
}

function valueFor(
  status: AuthStatus,
  user: { username?: string; roles: UserRole[] } | null,
  login: () => void,
  logout: () => void,
  error?: string,
): AuthContextType {
  const roles = user?.roles ?? [];
  const isViewer = !roles.some((r) => r !== 'viewer');
  return { status, error, username: user?.username, roles, role: primaryRole(roles), isViewer, login, logout, ...makeMasks(isViewer) };
}

async function createManager(): Promise<UserManager> {
  const cfg = await loadConfig();
  return new UserManager({
    authority: cfg.oidcAuthority,
    client_id: cfg.oidcClientId,
    redirect_uri: `${window.location.origin}/`,
    post_logout_redirect_uri: `${window.location.origin}/`,
    response_type: 'code', // authorization code with PKCE
    // preferred_username and the roles come with the strata-api scope,
    // a default scope of the client.
    scope: 'openid',
    automaticSilentRenew: true,
    userStore: new WebStorageStateStore({ store: window.sessionStorage }),
  });
}

function fromUser(u: User | null): { username?: string; roles: UserRole[] } | null {
  if (!u || u.expired) return null;
  return {
    username: (u.profile.preferred_username as string | undefined) ?? u.profile.sub,
    roles: rolesFromAccessToken(u.access_token),
  };
}

export const AuthProvider: React.FC<{ children: React.ReactNode; manager?: UserManager }> = ({ children, manager }) => {
  const [mgr, setMgr] = useState<UserManager | null>(manager ?? null);
  const [status, setStatus] = useState<AuthStatus>('loading');
  const [user, setUser] = useState<{ username?: string; roles: UserRole[] } | null>(null);
  const [error, setError] = useState<string | undefined>();

  useEffect(() => {
    let cancelled = false;
    let um: UserManager | null = manager ?? null;
    const onLoaded = (u: User) => {
      setUser(fromUser(u));
      setStatus('authenticated');
    };
    const onGone = () => {
      setUser(null);
      setStatus('anonymous');
    };
    (async () => {
      try {
        um = um ?? (await createManager());
        if (cancelled) return;
        setMgr(um);
        um.events.addUserLoaded(onLoaded);
        um.events.addUserUnloaded(onGone);
        um.events.addAccessTokenExpired(onGone);
        const params = new URLSearchParams(window.location.search);
        if (params.has('error') && params.has('state')) {
          // The provider refused the sign-in (RFC 6749 4.1.2.1).
          window.history.replaceState({}, document.title, window.location.pathname);
          throw new Error(params.get('error_description') || params.get('error') || 'sign-in failed');
        }
        if (params.has('code') && params.has('state')) {
          await um.signinRedirectCallback();
          window.history.replaceState({}, document.title, window.location.pathname);
        }
        const u = await um.getUser();
        if (cancelled) return;
        const info = fromUser(u);
        setUser(info);
        setStatus(info ? 'authenticated' : 'anonymous');
      } catch (e) {
        if (!cancelled) {
          setError(e instanceof Error ? e.message : String(e));
          setStatus('error');
        }
      }
    })();
    return () => {
      cancelled = true;
      if (um) {
        um.events.removeUserLoaded(onLoaded);
        um.events.removeUserUnloaded(onGone);
        um.events.removeAccessTokenExpired(onGone);
      }
    };
  }, [manager]);

  const value = useMemo(() => {
    const login = () => void mgr?.signinRedirect();
    const logout = () => void mgr?.signoutRedirect();
    return valueFor(status, user, login, logout, error);
  }, [mgr, status, user, error]);

  // The API client asks for the current token on every call and sends the
  // user back to the login page when the API answers 401.
  useEffect(() => {
    setAuthHandlers({
      token: async () => (mgr ? (await mgr.getUser())?.access_token : undefined),
      unauthorized: () => {
        if (mgr) void mgr.removeUser().then(() => setStatus('anonymous'));
      },
    });
  }, [mgr]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

// StaticAuthProvider is a signed-in user with fixed roles, for tests and
// component previews.
export const StaticAuthProvider: React.FC<{ children: React.ReactNode; roles: UserRole[]; username?: string }> = ({
  children,
  roles,
  username = 'test-user',
}) => {
  const value = useMemo(() => valueFor('authenticated', { username, roles }, () => {}, () => {}), [roles, username]);
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
