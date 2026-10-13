import React from 'react';
import { AuthProvider, useAuth } from './context/AuthContext';
import { OverviewPage } from './pages/OverviewPage';
import { EventsPage } from './pages/EventsPage';
import { EventDetailPage } from './pages/EventDetailPage';
import { LoginPage } from './pages/LoginPage';
import { PoliciesPage } from './pages/PoliciesPage';
import { FleetPage } from './pages/FleetPage';
import { useRoute } from './router';

export const AppContent: React.FC = () => {
  const { status } = useAuth();
  const route = useRoute();
  if (status !== 'authenticated') return <LoginPage />;
  switch (route.page) {
    case 'events':
      return <EventsPage key={JSON.stringify(route.query ?? {})} route={route} />;
    case 'event':
      return <EventDetailPage key={route.blockId} blockId={route.blockId ?? ''} />;
    case 'policies':
      return <PoliciesPage />;
    case 'fleet':
      return <FleetPage />;
    default:
      return <OverviewPage key={JSON.stringify(route.query ?? {})} route={route} />;
  }
};

export const App: React.FC = () => {
  return (
    <AuthProvider>
      <AppContent />
    </AuthProvider>
  );
};

export default App;
