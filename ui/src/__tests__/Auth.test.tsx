import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import { UserManager } from 'oidc-client-ts';
import { AuthProvider, StaticAuthProvider } from '../context/AuthContext';
import { AppContent } from '../App';
import { Header } from '../components/layout/Header';
import { apiClient, setAuthHandlers, ApiError } from '../api/client';
import { rolesFromAccessToken, primaryRole } from '../auth/roles';
import { loadConfig, defaultConfig } from '../auth/config';
import i18n from '../i18n';

function jwt(payload: object): string {
  const b64 = (o: object) => btoa(JSON.stringify(o)).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
  return `${b64({ alg: 'RS256', typ: 'JWT' })}.${b64(payload)}.sig`;
}

// A UserManager stand-in: getUser returns the given user, sign-in and
// sign-out are recorded.
function fakeManager(user: object | null) {
  const listeners = () => ({ add: vi.fn(), remove: vi.fn() });
  const ev = { loaded: listeners(), unloaded: listeners(), expired: listeners() };
  return {
    getUser: vi.fn().mockResolvedValue(user),
    signinRedirect: vi.fn().mockResolvedValue(undefined),
    signoutRedirect: vi.fn().mockResolvedValue(undefined),
    signinRedirectCallback: vi.fn(),
    removeUser: vi.fn().mockResolvedValue(undefined),
    events: {
      addUserLoaded: ev.loaded.add, removeUserLoaded: ev.loaded.remove,
      addUserUnloaded: ev.unloaded.add, removeUserUnloaded: ev.unloaded.remove,
      addAccessTokenExpired: ev.expired.add, removeAccessTokenExpired: ev.expired.remove,
    },
  } as unknown as UserManager & { signinRedirect: ReturnType<typeof vi.fn>; signoutRedirect: ReturnType<typeof vi.fn> };
}

const operatorUser = {
  expired: false,
  access_token: jwt({ realm_access: { roles: ['operator', 'offline_access'] } }),
  profile: { sub: 'u1', preferred_username: 'lab-operator' },
};

const fetchMock = vi.fn();

beforeEach(() => {
  fetchMock.mockReset();
  vi.stubGlobal('fetch', fetchMock);
  fetchMock.mockResolvedValue(new Response(JSON.stringify({ version: '0.1.0', commit: '', api_version: 'v1' }), { status: 200 }));
  void i18n.changeLanguage('vi');
});
afterEach(() => {
  vi.unstubAllGlobals();
  setAuthHandlers({ token: async () => undefined, unauthorized: () => {} });
});

describe('roles from the access token', () => {
  it('keeps the four known roles only', () => {
    expect(rolesFromAccessToken(jwt({ realm_access: { roles: ['approver', 'uma_authorization', 'viewer'] } }))).toEqual(['viewer', 'approver']);
    expect(rolesFromAccessToken(jwt({}))).toEqual([]);
    expect(rolesFromAccessToken('garbage')).toEqual([]);
    expect(primaryRole(['viewer', 'admin'])).toBe('admin');
    expect(primaryRole([])).toBeUndefined();
  });
});

describe('runtime config', () => {
  it('falls back to the lab defaults', async () => {
    const f = vi.fn().mockResolvedValue(new Response('nope', { status: 404 }));
    expect(await loadConfig(f as unknown as typeof fetch)).toEqual(defaultConfig);
    const g = vi.fn().mockResolvedValue(new Response(JSON.stringify({ oidcAuthority: 'https://sso.example.test/realms/strata' })));
    expect((await loadConfig(g as unknown as typeof fetch)).oidcAuthority).toBe('https://sso.example.test/realms/strata');
  });
});

describe('sign in and out', () => {
  it('shows the login page without a session and redirects to the provider', async () => {
    const mgr = fakeManager(null);
    render(<AuthProvider manager={mgr}><AppContent /></AuthProvider>);
    const btn = await screen.findByTestId('login-btn');
    expect(screen.queryByTestId('block-id-search-input')).not.toBeInTheDocument();
    fireEvent.click(btn);
    expect(mgr.signinRedirect).toHaveBeenCalledOnce();
  });

  it('shows the error the provider sent back', async () => {
    window.history.replaceState({}, '', '/?error=invalid_scope&error_description=Invalid+scopes&state=s1');
    render(<AuthProvider manager={fakeManager(null)}><AppContent /></AuthProvider>);
    expect(await screen.findByTestId('login-error')).toHaveTextContent('Invalid scopes');
    expect(window.location.search).toBe('');
  });

  it('shows the app with the user and role from the token, and signs out', async () => {
    const mgr = fakeManager(operatorUser);
    fetchMock.mockImplementation(async (url: string) =>
      url.endsWith('/version')
        ? new Response(JSON.stringify({ version: '0.1.0', commit: '', api_version: 'v1' }))
        : new Response(JSON.stringify({ events: [], total_matched: 0 })),
    );
    render(<AuthProvider manager={mgr}><AppContent /></AuthProvider>);
    expect(await screen.findByTestId('current-user')).toHaveTextContent('lab-operator');
    expect(screen.getByTestId('current-role')).toHaveTextContent('Operator');
    expect(await screen.findByTestId('cp-version')).toHaveTextContent('0.1.0');
    fireEvent.click(screen.getByTestId('logout-btn'));
    expect(mgr.signoutRedirect).toHaveBeenCalledOnce();
  });

  it('sends the access token and ends the session on 401', async () => {
    const mgr = fakeManager(operatorUser);
    render(<AuthProvider manager={mgr}><div /></AuthProvider>);
    await waitFor(() => expect(mgr.getUser).toHaveBeenCalled());

    fetchMock.mockResolvedValueOnce(new Response(JSON.stringify({ version: '0.1.0', commit: '', api_version: 'v1' })));
    await act(async () => { await apiClient.getVersion(); });
    const headers = fetchMock.mock.calls.at(-1)![1].headers as Headers;
    expect(headers.get('Authorization')).toBe(`Bearer ${operatorUser.access_token}`);

    fetchMock.mockResolvedValueOnce(new Response(JSON.stringify({ error: 'authentication required', code: 401 }), { status: 401 }));
    await act(async () => {
      await expect(apiClient.getVersion()).rejects.toBeInstanceOf(ApiError);
    });
    expect(mgr.removeUser).toHaveBeenCalledOnce();
  });
});

describe('language', () => {
  it('starts in English, switches to Vietnamese and remembers it', async () => {
    await i18n.changeLanguage('en');
    render(<StaticAuthProvider roles={['viewer']}><Header onSearchBlockId={() => {}} /></StaticAuthProvider>);
    expect(screen.getByTestId('logout-btn')).toHaveAttribute('title', 'Sign out');
    expect(screen.getByTestId('language-toggle-btn')).toHaveTextContent('EN');
    fireEvent.click(screen.getByTestId('language-toggle-btn'));
    await waitFor(() => expect(screen.getByTestId('logout-btn')).toHaveAttribute('title', 'Đăng xuất'));
    expect(window.localStorage.getItem('strata.lang')).toBe('vi');
    await act(async () => { await i18n.changeLanguage('en'); });
  });
});
