import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { formatBytes, actorName } from '../components/ui';
import { ApplicationScope } from '../components/applications/ApplicationScope';
import { navItems } from '../components/layout/AppShell';
import { apiClient } from '../api/client';
import i18n from '../i18n';

beforeEach(() => {
  vi.restoreAllMocks();
  void i18n.changeLanguage('en');
});

describe('UI review fixes', () => {
  it('formats byte counts', () => {
    expect(formatBytes(2147483648, 'en')).toBe('2 GiB');
    expect(formatBytes('73964', 'en')).toBe('72.2 KiB');
    expect(formatBytes(512, 'en')).toBe('512 B');
    expect(formatBytes(undefined, 'en')).toBe('—');
    expect(formatBytes('n/a', 'en')).toBe('—');
  });

  it('shows the name a record was made by, not its subject', () => {
    expect(actorName('lab-operator (oidc:8e1c203c-c445-485f-997b-94099ae4f565)')).toBe('lab-operator');
    expect(actorName('lab-admin (bb7d159d-43a0)')).toBe('lab-admin');
    expect(actorName('system')).toBe('system');
    expect(actorName(undefined)).toBe('');
  });

  it('says there is no application instead of showing a blank page', async () => {
    vi.spyOn(apiClient, 'listApplications').mockResolvedValue({ applications: [], next_cursor: '' } as never);
    render(<ApplicationScope application="" environment="" onChange={() => {}} />);
    expect(await screen.findByTestId('scope-no-applications')).toHaveTextContent('There is no application yet');
  });

  it('asks to choose when applications exist', async () => {
    vi.spyOn(apiClient, 'listApplications').mockResolvedValue({ applications: [{ id: 'a1', name: 'example-shop', environments: [{ id: 'e1', name: 'prod' }] }], next_cursor: '' } as never);
    render(<ApplicationScope application="" environment="" onChange={() => {}} />);
    expect(await screen.findByTestId('scope-choose')).toBeInTheDocument();
  });

  it('starts the menu with the overview and gives every page its own icon', () => {
    expect(navItems[0].page).toBe('overview');
    const icons = navItems.map((n) => n.icon);
    expect(new Set(icons).size).toBe(icons.length);
    // groups are contiguous, so each heading appears once
    const groups = navItems.map((n) => n.group).filter((g, i, a) => i === 0 || a[i - 1] !== g);
    expect(groups).toEqual(['monitor', 'protect', 'operate', 'admin']);
  });
});
