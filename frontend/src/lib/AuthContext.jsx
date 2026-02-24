import { createContext, useContext, useEffect, useState, useCallback } from 'react';
import { getAuthToken, setAuth, clearStoredAuth, setOnUnauthorized } from './api.js';

const AuthContext = createContext(null);

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}

export default function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  function doLogout() {
    clearStoredAuth();
    setUser(null);
  }

  // Register the global 401 handler so apiFetch can trigger logout
  useEffect(() => {
    setOnUnauthorized(() => doLogout());
    return () => setOnUnauthorized(null);
  }, []);

  // Validate stored token on mount
  useEffect(() => {
    const token = getAuthToken();
    if (!token) {
      setLoading(false);
      return;
    }

    fetch('/api/auth/me', {
      headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' },
    })
      .then((res) => {
        if (!res.ok) throw new Error('Invalid token');
        return res.json();
      })
      .then((data) => {
        if (data?.user) {
          setUser(data.user);
          setAuth({ user: data.user });
        } else {
          doLogout();
        }
      })
      .catch(() => {
        doLogout();
      })
      .finally(() => setLoading(false));
  }, []);

  const login = useCallback(async (username, password) => {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({ username, password }),
    });

    const data = await res.json().catch(() => ({}));

    if (!res.ok) {
      throw new Error(data?.error || 'Login failed');
    }

    if (data.token && data.user) {
      setAuth({ token: data.token, user: data.user });
      setUser(data.user);
    } else {
      throw new Error('Invalid login response');
    }
  }, []);

  const logout = useCallback(() => {
    doLogout();
  }, []);

  return (
    <AuthContext.Provider value={{ user, loading, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}
