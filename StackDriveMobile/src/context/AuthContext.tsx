import React, { createContext, useContext, useState, useCallback, useEffect } from 'react';
import AsyncStorage from '@react-native-async-storage/async-storage';
import api, { onAuthExpired } from '../services/api';

interface User {
  id: string;
  email: string;
  aws_connected?: boolean;
  created_at?: string;
  last_login_at?: string;
  last_login_device?: string;
  last_login_ip?: string;
  aws_account_id?: string;
  aws_region?: string;
  quarantine_bucket?: string;
  secure_bucket?: string;
  kms_key_arn?: string;
  [key: string]: any;
}

interface AuthContextType {
  user: User | null;
  loading: boolean;
  isLoggingOut: boolean;
  login: (userData: User) => Promise<void>;
  logout: () => Promise<void>;
  updateUser: (userData: User) => Promise<void>;
}

const AuthContext = createContext<AuthContextType>({
  user: null,
  loading: true,
  isLoggingOut: false,
  login: async () => {},
  logout: async () => {},
  updateUser: async () => {},
});

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [isLoggingOut, setIsLoggingOut] = useState(false);

  // Restore session on mount
  useEffect(() => {
    const restoreSession = async () => {
      const token = await api.getToken();
      if (token) {
        try {
          const data = await api.getMe();
          setUser(data.user);
          await AsyncStorage.setItem('stackdrive_session', JSON.stringify({ user: data.user }));
        } catch (e) {
          await api.logout();
        }
      }
      setLoading(false);
    };
    restoreSession();
  }, []);

  // Listen for auth expiry
  useEffect(() => {
    const unsubscribe = onAuthExpired(() => {
      setUser(null);
      setLoading(false);
    });
    return unsubscribe;
  }, []);

  const login = useCallback(async (userData: User) => {
    setUser(userData);
    await AsyncStorage.setItem('stackdrive_session', JSON.stringify({ user: userData }));
  }, []);

  const logout = useCallback(async () => {
    setIsLoggingOut(true);
    try {
      await api.logout();
    } catch (e) {
      console.warn('Logout failed:', e);
    }
    setTimeout(() => {
      setUser(null);
      setIsLoggingOut(false);
    }, 2500);
  }, []);

  const updateUser = useCallback(async (updatedUser: User) => {
    setUser(updatedUser);
    const session = JSON.parse(await AsyncStorage.getItem('stackdrive_session') || '{}');
    session.user = updatedUser;
    await AsyncStorage.setItem('stackdrive_session', JSON.stringify(session));
  }, []);

  return (
    <AuthContext.Provider value={{ user, loading, isLoggingOut, login, logout, updateUser }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}
