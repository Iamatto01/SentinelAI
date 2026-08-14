import React, { createContext, useContext, useEffect, useState, useCallback } from 'react'
import { api, setToken, getToken } from './api.js'

const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let mounted = true
    if (!getToken()) { setLoading(false); return }
    api.me()
      .then((u) => { if (mounted) setUser(u) })
      .catch(() => { setToken(null) })
      .finally(() => mounted && setLoading(false))
    return () => { mounted = false }
  }, [])

  const login = useCallback(async (username, password) => {
    const res = await api.login(username, password)
    setToken(res.token)
    setUser(res.user)
    return res.user
  }, [])

  const logout = useCallback(() => { setToken(null); setUser(null) }, [])

  return (
    <AuthContext.Provider value={{ user, loading, login, logout, setUser, isAuthed: !!user }}>
      {children}
    </AuthContext.Provider>
  )
}

export const useAuth = () => useContext(AuthContext)
