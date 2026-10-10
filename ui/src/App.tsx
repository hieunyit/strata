import React from 'react';
import { AuthProvider } from './context/AuthContext';
import { EventsPage } from './pages/EventsPage';

export const App: React.FC = () => {
  return (
    <AuthProvider>
      <EventsPage />
    </AuthProvider>
  );
};

export default App;
