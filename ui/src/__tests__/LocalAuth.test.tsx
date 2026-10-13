import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { AuthProvider, StaticAuthProvider } from '../context/AuthContext';
import { AppContent } from '../App';
import { UsersPage } from '../pages/UsersPage';
import { AppShell } from '../components/layout/AppShell';
import { setAuthHandlers, fetchAuthMethods } from '../api/client';
import i18n from '../i18n';

type Handler = (init: RequestInit | undefined) => Response | Promise<Response>;

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status });

// A control plane stand-in: routes by method and path, records the calls.
function server(routes: Record<string, Handler>) {
  const calls: { key: string; init?: RequestInit }[] = [];
  const f = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input), 'http://ui.example.test');
    const key = `${(init?.method ?? 'GET').toUpperCase()} ${url.pathname}`;
    calls.push({ key, init });
    const h = routes[key];
    if (h) return h(init);
    if (key === 'GET /v1/version') return json({ version: '0.10.0', commit: '', api_version: 'v1' });
    return json({ error: 'not found', code: 404 }, 404);
  });
  vi.stubGlobal('fetch', f);
  return calls;
}

const authHeader = (init?: RequestInit) => new Headers(init?.headers).get('Authorization');

const session = {
  token: 'stl_abc',
  expires_at: new Date(Date.now() + 3600_000).toISOString(),
  username: 'alice',
  roles: ['operator'],
};

beforeEach(() => {
  window.sessionStorage.clear();
  window.location.hash = '';
  void i18n.changeLanguage('en');
});
afterEach(() => {
  vi.unstubAllGlobals();
  setAuthHandlers({ token: async () => undefined, unauthorized: () => {} });
});

describe('sign-in methods', () => {
  it('reads the methods and falls back to OIDC only on an older control plane', async () => {
    server({ 'GET /v1/auth/methods': () => json({ local: true, oidc: false }) });
    expect(await fetchAuthMethods()).toEqual({ local: true, oidc: false });
    server({});
    expect(await fetchAuthMethods()).toEqual({ local: false, oidc: true });
  });
});

describe('local accounts', () => {
  it('signs in with a password, sends the session token, and signs out', async () => {
    const calls = server({
      'GET /v1/auth/methods': () => json({ local: true, oidc: false }),
      'POST /v1/auth/login': (init) => {
        const body = JSON.parse(String(init?.body));
        return body.password === 'correct horse battery' ? json(session) : json({ error: 'invalid', code: 401 }, 401);
      },
      'GET /v1/stats/overview': () => json({ buckets: [], totals: {}, top_rules: [], top_routes: [], rules: {} }),
      'POST /v1/auth/logout': () => new Response(null, { status: 204 }),
    });
    render(<AuthProvider><AppContent /></AuthProvider>);

    await screen.findByTestId('password-login-form');
    expect(screen.queryByTestId('login-btn')).not.toBeInTheDocument(); // no SSO here

    fireEvent.change(screen.getByTestId('login-username'), { target: { value: 'alice' } });
    fireEvent.change(screen.getByTestId('login-password'), { target: { value: 'wrong password!' } });
    fireEvent.click(screen.getByTestId('password-login-btn'));
    expect(await screen.findByTestId('password-login-error')).toHaveTextContent(/Wrong username or password/);
    expect(screen.getByTestId('login-password')).toHaveValue('');

    fireEvent.change(screen.getByTestId('login-password'), { target: { value: 'correct horse battery' } });
    fireEvent.click(screen.getByTestId('password-login-btn'));
    expect(await screen.findByTestId('current-user')).toHaveTextContent('alice');
    expect(screen.getByTestId('current-role')).toHaveTextContent('Operator');
    expect(screen.getByTestId('change-password-open')).toBeInTheDocument();
    expect(screen.queryByTestId('nav-users')).not.toBeInTheDocument(); // admins only

    await waitFor(() => expect(calls.some((c) => c.key === 'GET /v1/stats/overview')).toBe(true));
    const stats = calls.find((c) => c.key === 'GET /v1/stats/overview');
    expect(authHeader(stats?.init)).toBe('Bearer stl_abc');
    expect(JSON.parse(window.sessionStorage.getItem('strata.localSession') ?? '{}').token).toBe('stl_abc');

    fireEvent.click(screen.getByTestId('logout-btn'));
    await screen.findByTestId('password-login-form');
    const out = calls.find((c) => c.key === 'POST /v1/auth/logout');
    expect(authHeader(out?.init)).toBe('Bearer stl_abc');
    expect(window.sessionStorage.getItem('strata.localSession')).toBeNull();
  });

  it('keeps the session over a reload and ends it when the API answers 401', async () => {
    window.sessionStorage.setItem('strata.localSession', JSON.stringify({ ...session, roles: ['admin'] }));
    server({
      'GET /v1/auth/methods': () => json({ local: true, oidc: false }),
      'GET /v1/stats/overview': () => json({ error: 'no session', code: 401 }, 401),
    });
    render(<AuthProvider><AppContent /></AuthProvider>);
    // signed in from storage, then the API refuses the token
    await screen.findByTestId('password-login-form');
    expect(window.sessionStorage.getItem('strata.localSession')).toBeNull();
  });

  it('drops an expired saved session', async () => {
    window.sessionStorage.setItem('strata.localSession', JSON.stringify({ ...session, expires_at: '2020-01-01T00:00:00Z' }));
    server({ 'GET /v1/auth/methods': () => json({ local: true, oidc: false }) });
    render(<AuthProvider><AppContent /></AuthProvider>);
    await screen.findByTestId('password-login-form');
    expect(window.sessionStorage.getItem('strata.localSession')).toBeNull();
  });

  it('says when the address is throttled', async () => {
    server({
      'GET /v1/auth/methods': () => json({ local: true, oidc: false }),
      'POST /v1/auth/login': () => json({ error: 'too many', code: 429 }, 429),
    });
    render(<AuthProvider><AppContent /></AuthProvider>);
    fireEvent.change(await screen.findByTestId('login-username'), { target: { value: 'alice' } });
    fireEvent.change(screen.getByTestId('login-password'), { target: { value: 'whatever password' } });
    fireEvent.click(screen.getByTestId('password-login-btn'));
    expect(await screen.findByTestId('password-login-error')).toHaveTextContent(/Too many attempts/);
  });
});

describe('Users page', () => {
  const users = [
    { username: 'admin', roles: ['admin'], disabled: false, locked: false, created_at: '2026-10-13T10:00:00Z', created_by: 'system:bootstrap',
      updated_at: '2026-10-13T10:00:00Z', password_changed_at: '2026-10-13T10:00:00Z', last_login_at: '2026-10-13T11:00:00Z' },
    { username: 'bob', roles: ['viewer'], disabled: false, locked: true, created_at: '2026-10-13T10:05:00Z', created_by: 'admin',
      updated_at: '2026-10-13T10:05:00Z', password_changed_at: '2026-10-13T10:05:00Z' },
  ];

  it('shows the nav entry to admins of a control plane with local accounts', () => {
    const { rerender } = render(
      <StaticAuthProvider roles={['admin']} methods={{ local: true, oidc: false }}><AppShell active="overview">x</AppShell></StaticAuthProvider>,
    );
    expect(screen.getAllByTestId('nav-users').length).toBeGreaterThan(0);
    rerender(<StaticAuthProvider roles={['admin']} methods={{ local: false, oidc: true }}><AppShell active="overview">x</AppShell></StaticAuthProvider>);
    expect(screen.queryByTestId('nav-users')).not.toBeInTheDocument();
  });

  it('lists accounts, creates one and unlocks one', async () => {
    const calls = server({
      'GET /v1/users': () => json({ users }),
      'POST /v1/users': (init) => json({ user: { ...users[1], ...JSON.parse(String(init?.body)), password: undefined } }),
      'PATCH /v1/users/bob': () => json({ user: { ...users[1], locked: false } }),
    });
    render(
      <StaticAuthProvider roles={['admin']} username="admin" isLocal methods={{ local: true, oidc: false }}><UsersPage /></StaticAuthProvider>,
    );
    const rows = await screen.findAllByTestId('user-row');
    expect(rows.map((r) => r.getAttribute('data-state'))).toEqual(['active', 'locked']);

    fireEvent.click(screen.getByTestId('new-user-btn'));
    fireEvent.change(screen.getByTestId('new-username'), { target: { value: 'Carol' } });
    fireEvent.change(screen.getByTestId('new-password'), { target: { value: 'short' } });
    expect(screen.getByTestId('create-user-btn')).toBeDisabled();
    fireEvent.change(screen.getByTestId('new-password'), { target: { value: 'a long enough password' } });
    fireEvent.click(screen.getByTestId('new-role-operator'));
    fireEvent.click(screen.getByTestId('create-user-btn'));
    await waitFor(() => expect(calls.some((c) => c.key === 'POST /v1/users')).toBe(true));
    const created = JSON.parse(String(calls.find((c) => c.key === 'POST /v1/users')?.init?.body));
    expect(created).toEqual({ username: 'carol', password: 'a long enough password', roles: ['viewer', 'operator'] });

    await waitFor(() => expect(screen.queryByTestId('create-user-form')).not.toBeInTheDocument());
    fireEvent.click(screen.getAllByTestId('edit-user-btn')[1]);
    fireEvent.click(await screen.findByTestId('unlock-user-btn'));
    await waitFor(() => expect(calls.some((c) => c.key === 'PATCH /v1/users/bob')).toBe(true));
    expect(JSON.parse(String(calls.find((c) => c.key === 'PATCH /v1/users/bob')?.init?.body))).toEqual({ unlock: true });
  });

  it('does not let an admin disable or delete their own account from the editor', async () => {
    server({ 'GET /v1/users': () => json({ users }) });
    render(
      <StaticAuthProvider roles={['admin']} username="admin" isLocal methods={{ local: true, oidc: false }}><UsersPage /></StaticAuthProvider>,
    );
    fireEvent.click((await screen.findAllByTestId('edit-user-btn'))[0]);
    expect(screen.getByTestId('edit-disabled')).toBeDisabled();
    expect(screen.queryByTestId('delete-user-btn')).not.toBeInTheDocument();
  });

  it('explains when the control plane has no local accounts', async () => {
    server({});
    render(<StaticAuthProvider roles={['admin']}><UsersPage /></StaticAuthProvider>);
    expect(await screen.findByText(/not enabled on this control plane/)).toBeInTheDocument();
  });
});

describe('Users route', () => {
  it('falls back to the overview for non-admins', async () => {
    server({ 'GET /v1/stats/overview': () => json({ buckets: [], totals: {}, top_rules: [], top_routes: [], rules: {} }) });
    window.location.hash = '#/users';
    render(<StaticAuthProvider roles={['operator']} methods={{ local: true, oidc: false }}><AppContent /></StaticAuthProvider>);
    expect(screen.queryByTestId('users-table')).not.toBeInTheDocument();
    expect(screen.queryByTestId('new-user-btn')).not.toBeInTheDocument();
    await waitFor(() => expect(document.querySelector('[data-testid=nav-overview][aria-current=page]')).not.toBeNull());
  });
});
