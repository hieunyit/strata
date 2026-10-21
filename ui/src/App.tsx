import React, { useState, useEffect } from 'react';
import { AuthProvider, useAuth } from './context/AuthContext';
import { ReleasesPage } from './pages/ReleasesPage';
import { SecurityPage } from './pages/SecurityPage';
import { HealthPage } from './pages/HealthPage';
import { ApplicationsPage } from './pages/ApplicationsPage';
import { OverviewPage } from './pages/OverviewPage';
import { MapPage } from './pages/MapPage';
import { EventsPage } from './pages/EventsPage';
import { EventDetailPage } from './pages/EventDetailPage';
import { LoginPage } from './pages/LoginPage';
import { ReviewsPage } from './pages/ReviewsPage';
import { PoliciesPage } from './pages/PoliciesPage';
import { FleetPage } from './pages/FleetPage';
import { UsersPage } from './pages/UsersPage';
import { AuditPage } from './pages/AuditPage';
import { useRoute } from './router';
import { useIdleTimeout } from './hooks/useIdleTimeout';
import { IdleTimeoutModal } from './components/layout/IdleTimeoutModal';
import { KeyboardHelpModal } from './components/layout/KeyboardHelpModal';
import { useKeyboardShortcuts } from './hooks/useKeyboardShortcuts';
import { apiClient } from './api/client';

export const AppContent: React.FC = () => {
  const { status, roles, scoped, logout } = useAuth();
  const route = useRoute();
  const [helpOpen, setHelpOpen] = useState(false);

  useKeyboardShortcuts({
    onSearchFocus: () => {
      const input = document.getElementById('block-id-search');
      if (input) {
        input.focus();
        (input as HTMLInputElement).select();
      }
    },
    onEscape: () => {
      setHelpOpen(false);
    },
    onHelpToggle: () => {
      setHelpOpen((prev) => !prev);
    },
  });

  const { isWarningOpen, secondsRemaining, staySignedIn, signOutNow } = useIdleTimeout({
    enabled: status === 'authenticated',
    onTimeout: logout,
    onActive: () => void apiClient.me().catch(() => {}),
  });

  const [demoIdle, setDemoIdle] = useState(false);
  useEffect(() => {
    (window as any).__showIdleDemo = () => setDemoIdle(true);
    (window as any).__hideIdleDemo = () => setDemoIdle(false);
  }, []);

  if (status !== 'authenticated') return <LoginPage />;

  const renderPage = () => {
    switch (route.page) {
      case 'releases':
        return scoped ? <ApplicationsPage/> : <ReleasesPage/>;
      case 'security':
        return <SecurityPage/>;
      case 'health':
        return <HealthPage/>;
      case 'applications':
        return <ApplicationsPage />;
      case 'map':
        return <MapPage key={JSON.stringify(route.query ?? {})} route={route} />;
      case 'events':
        return <EventsPage key={JSON.stringify(route.query ?? {})} route={route} />;
      case 'event':
        return <EventDetailPage key={route.blockId} blockId={route.blockId ?? ''} />;
      case 'reviews':
        return <ReviewsPage />;
      case 'policies':
        return <PoliciesPage />;
      case 'fleet':
        return <FleetPage />;
      case 'users':
        if (!scoped && roles.includes('admin')) return <UsersPage />;
        return <OverviewPage route={{ page: 'overview' }} />;
      case 'audit':
        if (!scoped && roles.includes('admin')) return <AuditPage />;
        return <OverviewPage route={{ page: 'overview' }} />;
      default:
        return <OverviewPage key={JSON.stringify(route.query ?? {})} route={route} />;
    }
  };

  return (
    <>
      <IdleTimeoutModal
        isOpen={isWarningOpen || demoIdle}
        secondsRemaining={demoIdle ? 45 : secondsRemaining}
        onStaySignedIn={() => {
          setDemoIdle(false);
          staySignedIn();
        }}
        onSignOut={signOutNow}
      />
      <KeyboardHelpModal
        isOpen={helpOpen}
        onClose={() => setHelpOpen(false)}
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
