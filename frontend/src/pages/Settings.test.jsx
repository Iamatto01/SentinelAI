import React from 'react'
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react'
import { describe, expect, it, vi, beforeEach } from 'vitest'
import Settings from './Settings.jsx'

let mockUser = { id: 'u1', username: 'analyst', role: 'client', email: 'analyst@example.com' }
const mockSetUser = vi.fn()

const mockMe = vi.fn()
const mockChangePassword = vi.fn()
const mockTelegramPairing = vi.fn()
const mockAiProviders = vi.fn()
const mockSendFeedback = vi.fn()

vi.mock('../lib/AuthContext.jsx', () => ({
  useAuth: () => ({
    user: mockUser,
    setUser: mockSetUser,
  }),
}))

vi.mock('../lib/ThemeContext.jsx', () => ({
  useTheme: () => ({
    theme: 'static_dark',
    setTheme: vi.fn(),
    blur: 0,
    setBlur: vi.fn(),
    opacity: 35,
    setOpacity: vi.fn(),
    isStatic: true,
    setIsStatic: vi.fn(),
    randomizeNow: vi.fn(),
    wallpapers: [],
    activeWallpaper: '',
  }),
}))

vi.mock('../components/AdminSubscriptionManager.jsx', () => ({
  default: () => <div data-testid="admin-subscription-manager">Subscription Manager</div>,
}))

vi.mock('../lib/api.js', () => ({
  api: {
    me: (...args) => mockMe(...args),
    changePassword: (...args) => mockChangePassword(...args),
    telegramPairing: (...args) => mockTelegramPairing(...args),
    aiProviders: (...args) => mockAiProviders(...args),
    sendFeedback: (...args) => mockSendFeedback(...args),
    updateMe: vi.fn().mockResolvedValue({}),
    pairTelegram: vi.fn().mockResolvedValue({}),
    unpairChannel: vi.fn().mockResolvedValue({}),
    saveAiSettings: vi.fn().mockResolvedValue({}),
    testAiProvider: vi.fn().mockResolvedValue({ success: true }),
  },
}))

function submitPasswordForm({ currentPassword = 'OldPassword1!', newPassword, confirm }) {
  fireEvent.change(screen.getByLabelText(/^current password$/i), {
    target: { value: currentPassword },
  })
  fireEvent.change(screen.getByLabelText(/^new password$/i), {
    target: { value: newPassword },
  })
  fireEvent.change(screen.getByLabelText(/^confirm new password$/i), {
    target: { value: confirm ?? newPassword },
  })
  fireEvent.click(screen.getByRole('button', { name: /update password/i }))
}

describe('Settings Page (Medium Finding #12)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockUser = { id: 'u1', username: 'analyst', role: 'client', email: 'analyst@example.com' }
    mockMe.mockResolvedValue({ email: 'analyst@example.com' })
    mockTelegramPairing.mockResolvedValue({ telegram: { paired: false }, discord: { paired: false } })
    mockAiProviders.mockResolvedValue({ providers: [] })
    mockChangePassword.mockResolvedValue({ ok: true, message: 'Password updated successfully!' })
    mockSendFeedback.mockResolvedValue({ message: 'Feedback sent!' })
    window.history.pushState({}, '', '/app/settings')
  })

  describe('Password complexity alignment', () => {
    it('shows updated 8+ char complexity helper text instead of legacy Min 4 characters', async () => {
      render(<Settings />)

      await waitFor(() => expect(mockMe).toHaveBeenCalled())
      expect(screen.queryByText(/min 4 characters/i)).toBeNull()
      expect(screen.getByText(/min 8 chars/i)).toBeInTheDocument()
      expect(screen.getByText(/uppercase & lowercase letters, a number, and a special symbol/i)).toBeInTheDocument()
    })

    it.each([
      { label: 'shorter than 8 chars', value: 'Ab1!xyz', expected: /at least 8 characters long/i },
      { label: 'missing lowercase letter', value: 'ABCDEFG1!', expected: /at least one lowercase letter/i },
      { label: 'missing uppercase letter', value: 'abcdefg1!', expected: /at least one uppercase letter/i },
      { label: 'missing digit', value: 'Abcdefgh!', expected: /at least one digit/i },
      { label: 'missing special character', value: 'Abcdefg1', expected: /at least one special character/i },
    ])('rejects password $label upfront without calling api.changePassword', async ({ value, expected }) => {
      render(<Settings />)

      await waitFor(() => expect(mockMe).toHaveBeenCalled())
      submitPasswordForm({ newPassword: value })

      const alert = await screen.findByRole('alert')
      expect(alert).toHaveTextContent(expected)
      expect(mockChangePassword).not.toHaveBeenCalled()
    })

    it('rejects mismatched confirmation password before calling api.changePassword', async () => {
      render(<Settings />)

      await waitFor(() => expect(mockMe).toHaveBeenCalled())
      submitPasswordForm({ newPassword: 'StrongPass1!', confirm: 'StrongPass2!' })

      const alert = await screen.findByRole('alert')
      expect(alert).toHaveTextContent(/do not match/i)
      expect(mockChangePassword).not.toHaveBeenCalled()
    })

    it('submits password meeting all 5 complexity rules to api.changePassword', async () => {
      render(<Settings />)

      await waitFor(() => expect(mockMe).toHaveBeenCalled())
      submitPasswordForm({ currentPassword: 'OldPassword1!', newPassword: 'StrongPass1!' })

      await waitFor(() => {
        expect(mockChangePassword).toHaveBeenCalledWith('OldPassword1!', 'StrongPass1!')
      })
      expect(await screen.findByText(/password updated successfully!/i)).toBeInTheDocument()
    })
  })

  describe('URL ?tab= query routing', () => {
    it('activates Telegram tab when ?tab=telegram is present', async () => {
      window.history.pushState({}, '', '/app/settings?tab=telegram')
      render(<Settings />)

      await waitFor(() => expect(mockTelegramPairing).toHaveBeenCalled())
      expect(screen.getByRole('button', { name: /telegram bot/i })).toHaveAttribute('aria-pressed', 'true')
      expect(screen.getByRole('heading', { name: /telegram bot integration/i })).toBeInTheDocument()
      expect(screen.queryByRole('heading', { name: /discord & other bots integration/i })).toBeNull()
      expect(screen.queryByRole('heading', { name: /anonymous feedback & bug report/i })).toBeNull()
      expect(screen.queryByRole('heading', { name: /security credentials/i })).toBeNull()
    })

    it('activates Discord tab when ?tab=discord is present', async () => {
      window.history.pushState({}, '', '/app/settings?tab=discord')
      render(<Settings />)

      await waitFor(() => expect(mockTelegramPairing).toHaveBeenCalled())
      expect(screen.getByRole('button', { name: /discord bot/i })).toHaveAttribute('aria-pressed', 'true')
      expect(screen.getByRole('heading', { name: /discord & other bots integration/i })).toBeInTheDocument()
      expect(screen.queryByRole('heading', { name: /telegram bot integration/i })).toBeNull()
      expect(screen.queryByRole('heading', { name: /anonymous feedback & bug report/i })).toBeNull()
      expect(screen.queryByRole('heading', { name: /security credentials/i })).toBeNull()
    })

    it('activates Feedback tab when ?tab=feedback is present', async () => {
      window.history.pushState({}, '', '/app/settings?tab=feedback')
      render(<Settings />)

      await waitFor(() => expect(mockTelegramPairing).toHaveBeenCalled())
      expect(screen.getByRole('button', { name: /^feedback$/i })).toHaveAttribute('aria-pressed', 'true')
      expect(screen.getByRole('heading', { name: /anonymous feedback & bug report/i })).toBeInTheDocument()
      expect(screen.queryByRole('heading', { name: /telegram bot integration/i })).toBeNull()
      expect(screen.queryByRole('heading', { name: /discord & other bots integration/i })).toBeNull()
      expect(screen.queryByRole('heading', { name: /security credentials/i })).toBeNull()
    })

    it('falls back to general tab instead of blank page when non-admin visits ?tab=ai or ?tab=subscriptions', async () => {
      window.history.pushState({}, '', '/app/settings?tab=ai')
      const { unmount } = render(<Settings />)

      await waitFor(() => expect(mockMe).toHaveBeenCalled())
      expect(screen.getByRole('button', { name: /general & wallpapers/i })).toHaveAttribute('aria-pressed', 'true')
      expect(screen.getByRole('heading', { name: /security credentials/i })).toBeInTheDocument()
      expect(screen.queryByRole('heading', { name: /ai provider api keys/i })).toBeNull()
      unmount()

      window.history.pushState({}, '', '/app/settings?tab=subscriptions')
      render(<Settings />)

      await waitFor(() => expect(mockMe).toHaveBeenCalledTimes(2))
      expect(screen.getByRole('button', { name: /general & wallpapers/i })).toHaveAttribute('aria-pressed', 'true')
      expect(screen.getByRole('heading', { name: /security credentials/i })).toBeInTheDocument()
      expect(screen.queryByTestId('admin-subscription-manager')).toBeNull()
    })

    it('allows ?tab=ai and ?tab=subscriptions for admin users', async () => {
      mockUser = { id: 'a1', username: 'admin', role: 'admin', email: 'admin@example.com' }
      window.history.pushState({}, '', '/app/settings?tab=ai')
      const { unmount } = render(<Settings />)

      await waitFor(() => expect(mockAiProviders).toHaveBeenCalled())
      expect(screen.getByRole('button', { name: /ai providers/i })).toHaveAttribute('aria-pressed', 'true')
      expect(screen.getByRole('heading', { name: /ai provider api keys/i })).toBeInTheDocument()
      unmount()

      window.history.pushState({}, '', '/app/settings?tab=subscriptions')
      render(<Settings />)

      await waitFor(() => expect(mockAiProviders).toHaveBeenCalledTimes(2))
      expect(screen.getByRole('button', { name: /subscription & plans manager/i })).toHaveAttribute('aria-pressed', 'true')
      expect(screen.getByTestId('admin-subscription-manager')).toBeInTheDocument()
    })
  })

  describe('Feedback error banner icon', () => {
    it('renders AlertCircle icon (and never CheckCircle2) in the feedback error banner', async () => {
      mockSendFeedback.mockRejectedValueOnce(new Error('Mail relay unavailable'))
      window.history.pushState({}, '', '/app/settings?tab=feedback')
      render(<Settings />)

      await waitFor(() => expect(mockTelegramPairing).toHaveBeenCalled())
      fireEvent.change(screen.getByPlaceholderText(/describe your bug, feedback, or suggestion/i), {
        target: { value: 'Bug report test payload' },
      })
      fireEvent.click(screen.getByRole('button', { name: /send anonymous feedback/i }))

      const alert = await screen.findByRole('alert')
      expect(alert).toHaveTextContent('Mail relay unavailable')
      expect(alert.querySelector('svg.lucide-circle-alert')).not.toBeNull()
      expect(alert.querySelector('svg.lucide-circle-check')).toBeNull()
      expect(within(alert).getByText('Mail relay unavailable')).toBeInTheDocument()
    })

    it('keeps CheckCircle2 icon for the feedback success banner', async () => {
      mockSendFeedback.mockResolvedValueOnce({ message: 'Feedback delivered!' })
      window.history.pushState({}, '', '/app/settings?tab=feedback')
      render(<Settings />)

      await waitFor(() => expect(mockTelegramPairing).toHaveBeenCalled())
      fireEvent.change(screen.getByPlaceholderText(/describe your bug, feedback, or suggestion/i), {
        target: { value: 'Great scanner UI' },
      })
      fireEvent.click(screen.getByRole('button', { name: /send anonymous feedback/i }))

      const successText = await screen.findByText('Feedback delivered!')
      const successBanner = successText.closest('div')
      expect(successBanner.querySelector('svg.lucide-circle-check')).not.toBeNull()
      expect(successBanner.querySelector('svg.lucide-circle-alert')).toBeNull()
    })
  })
})
