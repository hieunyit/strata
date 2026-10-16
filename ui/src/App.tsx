import React from 'react';
import { AuthProvider, useAuth } from './context/AuthContext';
import { OverviewPage } from './pages/OverviewPage';
import { EventsPage } from './pages/EventsPage';
import { EventDetailPage } from './pages/EventDetailPage';
import { LoginPage } from './pages/LoginPage';
import { PoliciesPage } from './pages/PoliciesPage';
import { FleetPage } from './pages/FleetPage';
import { UsersPage } from './pages/UsersPage';
import { AuditPage } from './pages/AuditPage';
import { useRoute } from './router';
import { useIdleTimeout } from './hooks/useIdleTimeout';
import { IdleTimeoutModal } from './components/layout/IdleTimeoutModal';
import { apiClient } from './api/client';

export const AppContent: React.FC = () => {
  const { status, roles, logout } = useAuth();
  const route = useRoute();

  const { isWarningOpen, secondsRemaining, staySignedIn, signOutNow } = useIdleTimeout({
    enabled: status === 'authenticated',
    onTimeout: logout,
    onActive: () => void apiClient.me().catch(() => {}),
  });

  if (status !== 'authenticated') return <LoginPage />;

  const renderPage = () => {
    switch (route.page) {
      case 'events':
        return <EventsPage key={JSON.stringify(route.query ?? {})} route={route} />;
      case 'event':
        return <EventDetailPage key={route.blockId} blockId={route.blockId ?? ''} />;
      case 'policies':
        return <PoliciesPage />;
      case 'fleet':
        return <FleetPage />;
      case 'users':
        if (roles.includes('admin')) return <UsersPage />;
        return <OverviewPage route={{ page: 'overview' }} />;
      case 'audit':
        if (roles.includes('admin')) return <AuditPage />;
        return <OverviewPage route={{ page: 'overview' }} />;
      default:
        return <OverviewPage key={JSON.stringify(route.query ?? {})} route={route} />;
    }
  };

  return (
    <>
      <IdleTimeoutModal
        isOpen={isWarningOpen}
        secondsRemaining={secondsRemaining}
        onStaySignedIn={staySignedIn}
        onSignOut={signOutNow}
      />
      {renderPage()}
    </>
  );
};

export const App: React.FC = () => {
  return (
    <AuthProvider>
      <AppContent />
    </AuthProvider>
  );
};

export default App;
