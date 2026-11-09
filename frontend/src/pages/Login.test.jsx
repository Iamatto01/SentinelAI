import React from 'react'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { describe, expect, it, vi, beforeEach } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import Login from './Login.jsx'

const mockLogin = vi.fn().mockResolvedValue({ id: 'u1', username: 'analyst' })
const mockSetUser = vi.fn()

vi.mock('../lib/AuthContext.jsx', () => ({
  useAuth: () => ({
    login: mockLogin,
    setUser: mockSetUser,
  }),
}))

vi.mock('../lib/ThemeContext.jsx', () => ({
  useTheme: () => ({
    isNight: true,
    toggleNightMode: vi.fn(),
  }),
}))

vi.mock('../lib/api.js', () => ({
  api: {
    register: vi.fn(),
  },
  setToken: vi.fn(),
}))

describe('Login Page', () => {
  beforeEach(() => {
    localStorage.clear()
    sessionStorage.clear()
    vi.clearAllMocks()
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ plans: [] }),
    })
  })

  it('renders login form with username, password, remember me checkbox, and valid autofill attributes', () => {
    render(
      <MemoryRouter>
        <Login />
      </MemoryRouter>
    )

    const userInput = screen.getByLabelText(/username or email/i)
    const passInput = screen.getByLabelText(/password/i)
    const rememberCheckbox = screen.getByLabelText(/remember me/i)

    expect(userInput).toBeInTheDocument()
    expect(userInput).toHaveAttribute('name', 'username')
    expect(userInput).toHaveAttribute('autocomplete', 'username')

    expect(passInput).toBeInTheDocument()
    expect(passInput).toHaveAttribute('name', 'password')
    expect(passInput).toHaveAttribute('autocomplete', 'current-password')

    expect(rememberCheckbox).toBeInTheDocument()
    expect(rememberCheckbox).toBeChecked()
  })

  it('loads remembered username from localStorage on mount', () => {
    localStorage.setItem('sentinel_remember_username', 'admin_analyst')
    localStorage.setItem('sentinel_remember_me', 'true')

    render(
      <MemoryRouter>
        <Login />
      </MemoryRouter>
    )

    const userInput = screen.getByLabelText(/username or email/i)
    expect(userInput).toHaveValue('admin_analyst')
  })

  it('saves username to localStorage when remember me is checked upon login', async () => {
    render(
      <MemoryRouter>
        <Login />
      </MemoryRouter>
    )

    const userInput = screen.getByLabelText(/username or email/i)
    const passInput = screen.getByLabelText(/password/i)
    const submitBtn = screen.getByRole('button', { name: /sign in to platform/i })

    fireEvent.change(userInput, { target: { value: 'kali_operator' } })
    fireEvent.change(passInput, { target: { value: 'secret123' } })
    fireEvent.click(submitBtn)

    await waitFor(() => {
      expect(mockLogin).toHaveBeenCalledWith('kali_operator', 'secret123', true)
    })
    expect(localStorage.getItem('sentinel_remember_username')).toBe('kali_operator')
    expect(localStorage.getItem('sentinel_remember_me')).toBe('true')
  })

  it('clears remembered username from localStorage when remember me is unchecked', async () => {
    localStorage.setItem('sentinel_remember_username', 'old_user')

    render(
      <MemoryRouter>
        <Login />
      </MemoryRouter>
    )

    const rememberCheckbox = screen.getByLabelText(/remember me/i)
    fireEvent.click(rememberCheckbox)
    expect(rememberCheckbox).not.toBeChecked()

    const userInput = screen.getByLabelText(/username or email/i)
    const passInput = screen.getByLabelText(/password/i)
    const submitBtn = screen.getByRole('button', { name: /sign in to platform/i })

    fireEvent.change(userInput, { target: { value: 'ephemeral_user' } })
    fireEvent.change(passInput, { target: { value: 'pass123' } })
    fireEvent.click(submitBtn)

    await waitFor(() => {
      expect(mockLogin).toHaveBeenCalledWith('ephemeral_user', 'pass123', false)
    })
    expect(localStorage.getItem('sentinel_remember_username')).toBeNull()
    expect(localStorage.getItem('sentinel_remember_me')).toBe('false')
  })
})
