import React from 'react';
import { AuthProvider, useAuth } from './context/AuthContext';
import { EventsPage } from './pages/EventsPage';
import { LoginPage } from './pages/LoginPage';
import { PoliciesPage } from './pages/PoliciesPage';
import { FleetPage } from './pages/FleetPage';
import { useRoute } from './router';

export const AppContent: React.FC = () => {
  const { status } = useAuth();
  const route = useRoute();
  if (status !== 'authenticated') return <LoginPage />;
  switch (route.page) {
    case 'policies':
      return <PoliciesPage />;
    case 'fleet':
      return <FleetPage />;
    default:
      return <EventsPage key={route.blockId ?? ''} initialBlockId={route.blockId} />;
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
