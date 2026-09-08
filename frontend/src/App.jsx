import React from 'react'
import { Routes, Route, Navigate, useLocation, useParams } from 'react-router-dom'
import { useAuth } from './lib/AuthContext.jsx'
import { ScanProvider } from './lib/ScanContext.jsx'
import { AiProvider } from './lib/AiContext.jsx'
import { ThemeProvider } from './lib/ThemeContext.jsx'
import Shell from './components/Shell.jsx'
import PublicLayout from './components/PublicLayout.jsx'
import Landing from './pages/Landing.jsx'
import About from './pages/About.jsx'
import Tools from './pages/Tools.jsx'
import Services from './pages/Services.jsx'
import Pricing from './pages/Pricing.jsx'
import Contact from './pages/Contact.jsx'
import Login from './pages/Login.jsx'
import Dashboard from './pages/Dashboard.jsx'
import Scans from './pages/Scans.jsx'
import ScanDetail from './pages/ScanDetail.jsx'
import Findings from './pages/Findings.jsx'
import Projects from './pages/Projects.jsx'
import Integrations from './pages/Integrations.jsx'
import Monitoring from './pages/Monitoring.jsx'
import Settings from './pages/Settings.jsx'
import Exploits from './pages/Exploits.jsx'
import ExploitCampaign from './pages/ExploitCampaign.jsx'
import GitHubAutomation from './pages/GitHubAutomation.jsx'
import Billing from './pages/Billing.jsx'
import ClientsManagement from './pages/ClientsManagement.jsx'
import KaliControl from './pages/KaliControl.jsx'
import Consultants from './pages/Consultants.jsx'
import CustomScripts from './pages/CustomScripts.jsx'

class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props)
    this.state = { hasError: false, error: null }
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error }
  }

  componentDidCatch(error, errorInfo) {
    console.error('UI Crash ErrorBoundary:', error, errorInfo)
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen grid place-items-center bg-slate-950 p-6 text-center">
          <div className="card p-8 max-w-md space-y-4 border border-red-500/30">
            <h2 className="text-xl font-bold text-slate-100">Something went wrong</h2>
            <p className="text-xs text-slate-400 font-mono bg-black/40 p-3 rounded-lg text-left overflow-auto max-h-32">
              {this.state.error?.toString() || 'Unknown UI Error'}
            </p>
            <button
              onClick={() => { this.setState({ hasError: false }); window.location.href = '/app/dashboard' }}
              className="btn-primary w-full justify-center"
            >
              Return to Dashboard
            </button>
          </div>
        </div>
      )
    }
    return this.props.children
  }
}

function RedirectScanDetail() {
  const { id } = useParams()
  return <Navigate to={`/app/scans/${id}`} replace />
}

function Protected({ children }) {
  const { isAuthed, loading } = useAuth()
  const loc = useLocation()
  if (loading) {
    return (
      <div className="min-h-screen grid place-items-center bg-ink-950">
        <div className="flex flex-col items-center gap-3">
          <div className="h-10 w-10 rounded-full border-2 border-ink-600 border-t-accent animate-spin" />
          <p className="text-sm text-slate-400">Initializing…</p>
        </div>
      </div>
    )
  }
  if (!isAuthed) return <Navigate to="/login" state={{ from: loc }} replace />
  return children
}

export default function App() {
  return (
    <ErrorBoundary>
      <ThemeProvider>
        <Routes>
          <Route path="/" element={<Landing />} />
          <Route path="/about" element={<About />} />
          <Route path="/tools" element={<Tools />} />
          <Route path="/services" element={<Services />} />
          <Route path="/pricing" element={<Pricing />} />
          <Route path="/contact" element={<Contact />} />
          <Route path="/login" element={<Login />} />
          
          {/* Top-level aliases for direct URL navigation */}
          <Route path="/dashboard" element={<Navigate to="/app/dashboard" replace />} />
          <Route path="/scans" element={<Navigate to="/app/scans" replace />} />
          <Route path="/scans/:id" element={<RedirectScanDetail />} />
          <Route path="/findings" element={<Navigate to="/app/findings" replace />} />
          <Route path="/projects" element={<Navigate to="/app/projects" replace />} />
          <Route path="/clients" element={<Navigate to="/app/clients" replace />} />
          <Route path="/monitoring" element={<Navigate to="/app/monitoring" replace />} />
          <Route path="/exploits" element={<Navigate to="/app/exploits" replace />} />
          <Route path="/integrations" element={<Navigate to="/app/integrations" replace />} />
          <Route path="/github" element={<Navigate to="/app/github" replace />} />
          <Route path="/billing" element={<Navigate to="/app/billing" replace />} />
          <Route path="/consultants" element={<Navigate to="/app/consultants" replace />} />
          <Route path="/kali-control" element={<Navigate to="/app/kali-control" replace />} />
          <Route path="/settings" element={<Navigate to="/app/settings" replace />} />

          {/* Main Protected Application */}
          <Route path="/app" element={<Protected><ScanProvider><AiProvider><Shell /></AiProvider></ScanProvider></Protected>}>
            <Route index element={<Navigate to="/app/dashboard" replace />} />
            <Route path="dashboard" element={<Dashboard />} />
            <Route path="kali-control" element={<KaliControl />} />
            <Route path="clients" element={<ClientsManagement />} />
            <Route path="scans" element={<Scans />} />
            <Route path="scans/:id" element={<ScanDetail />} />
            <Route path="findings" element={<Findings />} />
            <Route path="projects" element={<Projects />} />
            <Route path="monitoring" element={<Monitoring />} />
            <Route path="github" element={<GitHubAutomation />} />
            <Route path="billing" element={<Billing />} />
            <Route path="consultants" element={<Consultants />} />
            <Route path="integrations" element={<Integrations />} />
            <Route path="custom-scripts" element={<CustomScripts />} />
            <Route path="exploits" element={<Exploits />} />
            <Route path="exploits/:id" element={<ExploitCampaign />} />
            <Route path="settings" element={<Settings />} />
            <Route path="*" element={<Navigate to="/app/dashboard" replace />} />
          </Route>

          {/* Global Catch-all Redirect */}
          <Route path="*" element={<Navigate to="/app/dashboard" replace />} />
        </Routes>
      </ThemeProvider>
    </ErrorBoundary>
  )
}
