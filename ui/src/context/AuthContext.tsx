import React, { createContext, useContext, useState } from 'react';

export type UserRole = 'viewer' | 'operator' | 'admin';

interface AuthContextType {
  role: UserRole;
  setRole: (role: UserRole) => void;
  isViewer: boolean;
  maskIp: (ip: string) => string;
  maskSnippet: (snippet: string) => string;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  // Default to operator for full functionality, easily toggled via Header
  const [role, setRole] = useState<UserRole>('operator');

  const isViewer = role === 'viewer';

  const maskIp = (ip: string): string => {
    if (!isViewer || !ip) return ip;
    if (ip.includes('.')) {
      const parts = ip.split('.');
      if (parts.length === 4) {
        return `${parts[0]}.${parts[1]}.***.***`;
      }
    } else if (ip.includes(':')) {
      const parts = ip.split(':');
      if (parts.length > 2) {
        return `${parts[0]}:${parts[1]}:****:****`;
      }
    }
    return '***.***.***.***';
  };

  const maskSnippet = (snippet: string): string => {
    if (!isViewer) return snippet;
    return '[REDACTED FOR VIEWER ROLE]';
  };

  return (
    <AuthContext.Provider value={{ role, setRole, isViewer, maskIp, maskSnippet }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
