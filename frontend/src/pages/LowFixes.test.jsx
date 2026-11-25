import React from 'react'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it, vi, beforeEach } from 'vitest'
import Monitoring from './Monitoring.jsx'
import Tools from './Tools.jsx'
import Dashboard from './Dashboard.jsx'
import ScrollyNavbar from '../components/scrollytelling/ScrollyNavbar.jsx'
import { ThemeProvider, useTheme } from '../lib/ThemeContext.jsx'

vi.mock('../lib/AuthContext.jsx', () => ({
  useAuth: () => ({ user: { id: 'adm1', username: 'admin', role: 'admin', email: 'admin@test.local' } }),
}))

vi.mock('../components/PublicLayout.jsx', () => ({
  default: ({ children }) => <div data-testid="public-layout">{children}</div>,
}))

vi.mock('recharts', () => ({
  ResponsiveContainer: ({ children }) => <div>{children}</div>,
  PieChart: ({ children }) => <div>{children}</div>,
  Pie: () => <div />,
  Cell: () => <div />,
  Tooltip: () => null,
}))

const mockMonitors = vi.fn()
const mockAuditLogs = vi.fn()
const mockDashboard = vi.fn()
const mockStatus = vi.fn()
const mockKaliSysInfo = vi.fn()
const mockBillingSub = vi.fn()

vi.mock('../lib/api.js', () => ({
  apiFetch: vi.fn().mockResolvedValue({}),
  api: {
    monitors: (...a) => mockMonitors(...a),
    auditLogs: (...a) => mockAuditLogs(...a),
    monitor: vi.fn().mockResolvedValue({ events: [] }),
    dashboard: (...a) => mockDashboard(...a),
    status: (...a) => mockStatus(...a),
    kaliSystemInfo: (...a) => mockKaliSysInfo(...a),
    billingSubscription: (...a) => mockBillingSub(...a),
  },
}))

function ThemeProbe() {
  const { isNight, toggleNightMode } = useTheme()
  return (
    <button type="button" onClick={toggleNightMode}>
      mode:{isNight ? 'night' : 'day'}
    </button>
  )
}

describe('Low Audit Fixes (#14+)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.clear()
    document.documentElement.className = ''
    document.body.className = ''
    mockMonitors.mockResolvedValue([
      { id: 'm1', name: 'Prod Monitor', target: 'https://target.local', enabled: 1, interval_min: 60, last_risk: 4.5, status: 'idle' },
    ])
    mockAuditLogs.mockResolvedValue([])
    mockDashboard.mockResolvedValue({
      totals: { projects: 2, scans: 5, findings: 12 },
      severity: { critical: 1, high: 3, medium: 4, low: 2, info: 2 },
      recentScans: [{ id: 's1', target: 'https://target.local', status: 'completed', created_at: '2026-11-25T10:00:00.000Z' }],
      runningScans: 0,
      agentsCount: 53,
    })
    mockStatus.mockResolvedValue({ engine: { toolsAvailable: 42, totalTools: 48 } })
    mockKaliSysInfo.mockResolvedValue({ uptimeSec: 7200 })
    mockBillingSub.mockResolvedValue({ remainingQuota: 10 })
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify([]), { status: 200, headers: { 'content-type': 'application/json' } })
    )
  })

  it('Monitoring renders card selection and Play/Toggle/Delete as sibling non-nested buttons', async () => {
    const { container } = render(<Monitoring />)
    await waitFor(() => expect(screen.getByText('Prod Monitor')).toBeInTheDocument())
    expect(container.querySelector('button button')).toBeNull()
    expect(screen.getByRole('button', { name: /run scan now for prod monitor/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /disable prod monitor/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /delete prod monitor/i })).toBeInTheDocument()
  })

  it('ThemeContext toggles .dark on <html> together with .night / .day-mode on <body>', () => {
    render(
      <ThemeProvider>
        <ThemeProbe />
      </ThemeProvider>
    )
    expect(document.documentElement.classList.contains('dark')).toBe(false)
    expect(document.body.classList.contains('day-mode')).toBe(true)

    fireEvent.click(screen.getByRole('button', { name: /mode:day/i }))
    expect(document.documentElement.classList.contains('dark')).toBe(true)
    expect(document.body.classList.contains('night')).toBe(true)
    expect(document.body.classList.contains('day-mode')).toBe(false)
  })

  it('ScrollyNavbar uses whitespace-nowrap and closes Modules dropdown on Escape', () => {
    render(
      <MemoryRouter>
        <ThemeProvider>
          <ScrollyNavbar />
        </ThemeProvider>
      </MemoryRouter>
    )
    const modBtn = screen.getByRole('button', { name: /modules/i })
    expect(modBtn.className).toContain('whitespace-nowrap')
    fireEvent.click(modBtn)
    expect(modBtn).toHaveAttribute('aria-expanded', 'true')
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(modBtn).toHaveAttribute('aria-expanded', 'false')
  })

  it('Tools initializes with 53 personas and consistent 150+ CTA copy', () => {
    render(
      <MemoryRouter>
        <Tools />
      </MemoryRouter>
    )
    expect(screen.getByText('53 AI Personas')).toBeInTheDocument()
    expect(screen.getByText(/across 150\+ kali tools/i)).toBeInTheDocument()
  })

  it('Dashboard renders dynamic tool health and removes hardcoded 25 / 25 and 04 Nov 2026', async () => {
    render(
      <MemoryRouter>
        <ThemeProvider>
          <Dashboard />
        </ThemeProvider>
      </MemoryRouter>
    )
    await waitFor(() => expect(screen.getByText('42 / 48')).toBeInTheDocument())
    expect(screen.queryByText(/04 Nov 2026/)).toBeNull()
    expect(screen.queryByText('25 / 25')).toBeNull()
    expect(screen.getByText('42 Active Tools')).toBeInTheDocument()
  })
})
