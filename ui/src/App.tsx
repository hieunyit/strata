import React from 'react';
import { AuthProvider, useAuth } from './context/AuthContext';
import { EventsPage } from './pages/EventsPage';
import { LoginPage } from './pages/LoginPage';

export const AppContent: React.FC = () => {
  const { status } = useAuth();
  return status === 'authenticated' ? <EventsPage /> : <LoginPage />;
};

export const App: React.FC = () => {
  return (
    <AuthProvider>
      <AppContent />
    </AuthProvider>
  );
};

export default App;
