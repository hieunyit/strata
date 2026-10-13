import React from 'react';
import { AppShell } from '../components/layout/AppShell';
import { Page } from '../router';

export { ErrorBanner, formatTime } from '../components/ui';

// PageShell: the console frame for the pages that are not wide tables.
export const PageShell: React.FC<{ active: Page; children: React.ReactNode }> = ({ active, children }) => (
  <AppShell active={active}>{children}</AppShell>
);
