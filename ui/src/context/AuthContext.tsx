import React, { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react';
import { UserManager, WebStorageStateStore, User } from 'oidc-client-ts';
import { loadConfig } from '../auth/config';
import { UserRole, rolesFromAccessToken, primaryRole, knownRoles } from '../auth/roles';
import { setAuthHandlers, fetchAuthMethods, localLogin, apiClient, AuthMethods, LocalSession } from '../api/client';

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
  /** how this control plane accepts sign-ins */
  methods: AuthMethods;
  /** signed in with a local account (it can change its password here) */
  isLocal: boolean;
  /** single sign-on: redirects to the OIDC provider */
  login: () => void;
  /** a local account; throws the API's error (wrong password, throttled) */
  loginWithPassword: (username: string, password: string) => Promise<void>;
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

interface SessionUser {
  username?: string;
  roles: UserRole[];
}

const oidcOnly: AuthMethods = { local: false, oidc: true };

function valueFor(
  status: AuthStatus,
  user: SessionUser | null,
  actions: Pick<AuthContextType, 'login' | 'loginWithPassword' | 'logout'>,
  methods: AuthMethods = oidcOnly,
  isLocal = false,
  error?: string,
): AuthContextType {
  const roles = user?.roles ?? [];
  const isViewer = !roles.some((r) => r !== 'viewer');
  return {
    status, error, username: user?.username, roles, role: primaryRole(roles), isViewer, methods, isLocal,
    ...actions, ...makeMasks(isViewer),
  };
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

function fromUser(u: User | null): SessionUser | null {
  if (!u || u.expired) return null;
  return {
    username: (u.profile.preferred_username as string | undefined) ?? u.profile.sub,
    roles: rolesFromAccessToken(u.access_token),
  };
}

// A local session lives in sessionStorage, like the OIDC tokens: it ends
// with the tab, and storage that is unavailable only means signing in
// again after a reload.
const LOCAL_KEY = 'strata.localSession';

function readLocal(): LocalSession | null {
  try {
    const raw = window.sessionStorage.getItem(LOCAL_KEY);
    if (!raw) return null;
    const s = JSON.parse(raw) as LocalSession;
    if (typeof s.token !== 'string' || !s.token.startsWith('stl_') || !(Date.parse(s.expires_at) > Date.now())) {
      window.sessionStorage.removeItem(LOCAL_KEY);
      return null;
    }
    return s;
  } catch {
    return null;
  }
}

function writeLocal(s: LocalSession | null): void {
  try {
    if (s) window.sessionStorage.setItem(LOCAL_KEY, JSON.stringify(s));
    else window.sessionStorage.removeItem(LOCAL_KEY);
  } catch {
    // the session then lasts until a reload
  }
}

const localUser = (s: LocalSession): SessionUser => ({
  username: s.username,
  roles: knownRoles(s.roles ?? []),
});

export const AuthProvider: React.FC<{ children: React.ReactNode; manager?: UserManager }> = ({ children, manager }) => {
  const [mgr, setMgr] = useState<UserManager | null>(manager ?? null);
  const [status, setStatus] = useState<AuthStatus>('loading');
  const [user, setUser] = useState<SessionUser | null>(null);
  const [error, setError] = useState<string | undefined>();
  const [methods, setMethods] = useState<AuthMethods>(oidcOnly);
  // The local session in memory too: storage may be unavailable.
  const local = useRef<LocalSession | null>(null);
  const [isLocal, setIsLocal] = useState(false);

  const endLocal = useCallback(() => {
    local.current = null;
    writeLocal(null);
    setIsLocal(false);
    setUser(null);
    setStatus('anonymous');
  }, []);

  const startLocal = useCallback((s: LocalSession) => {
    local.current = s;
    writeLocal(s);
    setIsLocal(true);
    setUser(localUser(s));
    setError(undefined);
    setStatus('authenticated');
  }, []);

  useEffect(() => {
    let cancelled = false;
    let um: UserManager | null = manager ?? null;
    const onLoaded = (u: User) => {
      if (local.current) return;
      setUser(fromUser(u));
      setStatus('authenticated');
    };
    const onGone = () => {
      if (local.current) return;
      setUser(null);
      setStatus('anonymous');
    };
    (async () => {
      try {
        const m = await fetchAuthMethods();
        if (cancelled) return;
        setMethods(m);
        const saved = m.local ? readLocal() : null;
        if (saved) startLocal(saved);
        if (!m.oidc && !manager) {
          if (!saved) setStatus('anonymous');
          return;
        }
        um = um ?? (await createManager());
        if (cancelled) return;
        setMgr(um);
        um.events.addUserLoaded(onLoaded);
        um.events.addUserUnloaded(onGone);
        um.events.addAccessTokenExpired(onGone);
        if (saved) return;
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
  }, [manager, startLocal]);

  // A local session ends on its own at expires_at.
  useEffect(() => {
    const s = local.current;
    if (!isLocal || !s) return;
    const left = Date.parse(s.expires_at) - Date.now();
    const timer = window.setTimeout(endLocal, Math.max(0, Math.min(left, 2 ** 31 - 1)));
    return () => window.clearTimeout(timer);
  }, [isLocal, endLocal]);

  const value = useMemo(() => {
    const login = () => void mgr?.signinRedirect();
    const loginWithPassword = async (username: string, password: string) => {
      startLocal(await localLogin(username, password));
    };
    const logout = () => {
      if (local.current) {
        // End the session on the server too; the screen does not wait.
        void apiClient.logout().catch(() => {}).finally(endLocal);
        return;
      }
      void mgr?.signoutRedirect();
    };
    return valueFor(status, user, { login, loginWithPassword, logout }, methods, isLocal, error);
  }, [mgr, status, user, error, methods, isLocal, startLocal, endLocal]);

  // The API client asks for the current token on every call and sends the
  // user back to the login page when the API answers 401.
  useEffect(() => {
    setAuthHandlers({
      token: async () => local.current?.token ?? (mgr ? (await mgr.getUser())?.access_token : undefined),
      unauthorized: () => {
        if (local.current) endLocal();
        else if (mgr) void mgr.removeUser().then(() => setStatus('anonymous'));
      },
    });
  }, [mgr, endLocal]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

// StaticAuthProvider is a signed-in user with fixed roles, for tests and
// component previews.
export const StaticAuthProvider: React.FC<{
  children: React.ReactNode;
  roles: UserRole[];
  username?: string;
  isLocal?: boolean;
  methods?: AuthMethods;
}> = ({ children, roles, username = 'test-user', isLocal = false, methods = oidcOnly }) => {
  const value = useMemo(
    () => valueFor('authenticated', { username, roles }, { login: () => {}, loginWithPassword: async () => {}, logout: () => {} }, methods, isLocal),
    [roles, username, isLocal, methods],
  );
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
