import React from 'react'
import { render, screen, waitFor } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { AuthProvider, useAuth } from './AuthContext.jsx'

vi.mock('./api.js', () => ({
  api: { me: vi.fn().mockResolvedValue({ id: 'u1', username: 'analyst' }) },
  setToken: vi.fn(),
  getToken: vi.fn(() => null),
}))

function Consumer() {
  const { loading, isAuthed, user } = useAuth()
  return <output>{loading ? 'loading' : `${isAuthed}:${user?.username || 'anonymous'}`}</output>
}

describe('AuthContext', () => {
  it('starts unauthenticated when no token exists', async () => {
    render(<AuthProvider><Consumer /></AuthProvider>)
    await waitFor(() => expect(screen.getByText('false:anonymous')).toBeInTheDocument())
  })
})
