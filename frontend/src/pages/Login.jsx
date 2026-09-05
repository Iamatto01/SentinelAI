import React, { useState, useEffect, useRef } from 'react'
import { useNavigate, useLocation, Link } from 'react-router-dom'
import {
  ArrowLeft, Loader2, KeyRound, User, Eye, EyeOff, Sparkles,
  Mail, Check, AlertCircle, Lock
} from 'lucide-react'
import InspectorLogo from '../components/InspectorLogo.jsx'
import { useAuth } from '../lib/AuthContext.jsx'
import { api, setToken } from '../lib/api.js'

function EyeCursorTracker() {
  const [pupilOffset, setPupilOffset] = useState({ x: 0, y: 0 })
  const eyeRef = useRef(null)

  useEffect(() => {
    function handleMouseMove(e) {
      if (!eyeRef.current) return
      const rect = eyeRef.current.getBoundingClientRect()
      const eyeCenterX = rect.left + rect.width / 2
      const eyeCenterY = rect.top + rect.height / 2
      const deltaX = e.clientX - eyeCenterX
      const deltaY = e.clientY - eyeCenterY
      const distance = Math.hypot(deltaX, deltaY)
      const maxDistance = 4.5
      const factor = distance === 0 ? 0 : Math.min(distance / 150, 1) * maxDistance
      const angle = Math.atan2(deltaY, deltaX)
      setPupilOffset({
        x: Math.cos(angle) * factor,
        y: Math.sin(angle) * factor,
      })
    }
    window.addEventListener('mousemove', handleMouseMove)
    return () => window.removeEventListener('mousemove', handleMouseMove)
  }, [])

  return (
    <svg
      ref={eyeRef}
      width="18"
      height="18"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      className="text-cyan-400 drop-shadow-[0_0_10px_rgba(0,242,254,0.7)] transition-transform duration-75"
    >
      <path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z" />
      <circle cx={12 + pupilOffset.x} cy={12 + pupilOffset.y} r="3" fill="#00f2fe" stroke="none" />
    </svg>
  )
}

export default function Login() {
  const { login, setUser } = useAuth()
  const nav = useNavigate()
  const loc = useLocation()

  // Parse URL query params
  const searchParams = new URLSearchParams(loc.search)
  const initialMode = searchParams.get('mode') === 'register' ? 'register' : 'login'
  const initialPlan = 'trial'
  const initialInterval = 'monthly'

  const [mode, setMode] = useState(initialMode) // 'login' | 'register'
  const [username, setUsername] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [planId, setPlanId] = useState(initialPlan)
  const [interval, setInterval] = useState(initialInterval)
  const [showPassword, setShowPassword] = useState(false)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')

  // Force empty inputs on initial load to prevent browser autofill hijack
  useEffect(() => {
    setUsername('')
    setPassword('')
    setEmail('')
  }, [mode])

  async function submit(e) {
    e.preventDefault()
    setErr('')
    setBusy(true)
    try {
      if (mode === 'login') {
        await login(username.trim(), password)
        sessionStorage.setItem('sentinel_gate_trigger', 'true')
        nav(loc.state?.from?.pathname || '/app/dashboard', { replace: true })
      } else {
        // Register with Plan
        const res = await api.register({
          username: username.trim(),
          email: email.trim(),
          password,
          planId: planId || 'trial',
          billingInterval: interval,
          paymentProvider: 'stripe',
        })
        setToken(res.token)
        setUser(res.user)
        sessionStorage.setItem('sentinel_gate_trigger', 'true')
        nav('/app/dashboard', { replace: true })
      }
    } catch (e2) {
      const errMsg = e2.message || ''
      if (mode === 'login') {
        if (e2.status === 401 || errMsg.toLowerCase().includes('invalid') || errMsg.toLowerCase().includes('credential') || errMsg.toLowerCase().includes('failed (401)')) {
          setErr('Username or password is invalid')
        } else {
          setErr(errMsg || 'Username or password is invalid')
        }
      } else {
        setErr(errMsg || 'Registration failed')
      }
      setBusy(false)
    }
  }

  return (
    <div className="min-h-screen grid place-items-center grid-bg p-4 sm:p-6 relative overflow-hidden selection:bg-cyan-500 selection:text-slate-950">
      {/* Top-Left Back Button */}
      <Link
        to="/"
        className="fixed top-5 left-5 z-50 inline-flex items-center gap-2 px-4 py-2 rounded-full glass border border-white/15 hover:border-cyan-400/50 text-xs font-semibold text-slate-300 hover:text-cyan-300 transition-all duration-300 shadow-2xl group"
      >
        <ArrowLeft size={15} className="group-hover:-translate-x-1 transition-transform duration-200 text-cyan-400" />
        <span>Back to Landing Page</span>
      </Link>

      {/* Vision Ambient Glowing Meshes */}
      <div className="absolute top-1/3 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[500px] h-[500px] bg-cyan-500/15 rounded-full blur-[120px] pointer-events-none" />
      <div className="absolute bottom-1/3 left-1/2 -translate-x-1/2 translate-y-1/2 w-[500px] h-[500px] bg-purple-600/15 rounded-full blur-[120px] pointer-events-none" />

      {/* Main Centered Login / Register Container */}
      <div className="w-full max-w-lg relative z-10 my-auto motion-fade-up">
        {/* Header Logo & Title */}
        <div className="flex flex-col items-center mb-6 text-center">
          <div className="relative mb-3 group">
            <div className="absolute -inset-3 rounded-full bg-gradient-to-r from-cyan-400 via-blue-600 to-purple-600 opacity-60 blur-xl group-hover:opacity-90 transition duration-500" />
            <div className="relative">
              <InspectorLogo size={52} />
            </div>
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">SentinelAI</h1>
          <p className="text-[10px] uppercase tracking-[0.25em] text-cyan-400 font-extrabold mt-1 flex items-center gap-1.5 justify-center">
            <Sparkles size={12} className="text-cyan-300 animate-pulse" /> Autonomous Security Suite
          </p>
        </div>

        {/* Tab Switcher */}
        <div className="flex rounded-2xl bg-slate-900/80 p-1 border border-white/10 mb-4">
          <button
            type="button"
            onClick={() => { setMode('login'); setErr('') }}
            className={`flex-1 py-2 text-xs font-bold rounded-xl transition-all cursor-pointer ${
              mode === 'login'
                ? 'bg-cyan-500 text-slate-950 shadow-lg shadow-cyan-500/20'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            Sign In
          </button>
          <button
            type="button"
            onClick={() => { setMode('register'); setErr('') }}
            className={`flex-1 py-2 text-xs font-bold rounded-xl transition-all cursor-pointer ${
              mode === 'register'
                ? 'bg-cyan-500 text-slate-950 shadow-lg shadow-cyan-500/20'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            Create Account (Free Trial)
          </button>
        </div>

        {/* Vision UI Form Card */}
        <form
          onSubmit={submit}
          autoComplete="off"
          className="glass rounded-3xl border border-white/20 p-6 sm:p-7 shadow-2xl space-y-4 relative bg-slate-950/75"
        >
          {/* Hidden Dummy Inputs to prevent Chrome/Edge from autofilling saved credentials */}
          <input type="text" name="fakeusernameremembered" style={{ display: 'none' }} tabIndex={-1} autoComplete="off" />
          <input type="password" name="fakepasswordremembered" style={{ display: 'none' }} tabIndex={-1} autoComplete="off" />

          <div className="space-y-1">
            <label className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-1.5">
              <User size={13} className="text-cyan-400" /> Username
            </label>
            <input
              name="sentinel_auth_user"
              className="input py-2.5 text-sm text-slate-100 placeholder-slate-500 focus:border-cyan-400 transition-all"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="Username"
              autoComplete="new-password"
              required
            />
          </div>

          {mode === 'register' && (
            <div className="space-y-1">
              <label className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-1.5">
                <Mail size={13} className="text-cyan-400" /> Email Address
              </label>
              <input
                name="sentinel_auth_email"
                type="email"
                className="input py-2.5 text-sm text-slate-100 placeholder-slate-500 focus:border-cyan-400 transition-all"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="you@company.com"
                autoComplete="off"
                required
              />
            </div>
          )}

          <div className="space-y-1">
            <label className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-1.5">
              <KeyRound size={13} className="text-cyan-400" /> Password
            </label>
            <div className="relative flex items-center">
              <input
                name="sentinel_auth_pass"
                type={showPassword ? 'text' : 'password'}
                className="input py-2.5 pr-11 text-sm text-slate-100 placeholder-slate-500 focus:border-cyan-400 transition-all"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                autoComplete="new-password"
                required
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-3 p-1 rounded-lg hover:bg-white/10 text-slate-400 hover:text-cyan-300 transition-colors focus:outline-none"
                title={showPassword ? 'Hide password' : 'Reveal password'}
              >
                {showPassword ? <Eye size={16} className="text-cyan-400" /> : <EyeOff size={16} className="text-slate-400" />}
              </button>
            </div>
          </div>

          {/* Registration Plan Selection (Free Trial active, Paid tiers locked for Beta) */}
          {mode === 'register' && (
            <div className="space-y-2.5 pt-2 border-t border-white/10">
              <div className="flex items-center justify-between text-xs">
                <span className="font-bold text-slate-200">Select Tier:</span>
                <span className="text-[10px] text-cyan-300 font-mono flex items-center gap-1">
                  <Sparkles size={11} /> Community Beta Preview
                </span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
                {/* 1. Free Trial Card - ACTIVE */}
                <button
                  type="button"
                  onClick={() => setPlanId('trial')}
                  className="p-3 rounded-2xl border-2 border-cyan-400 bg-gradient-to-br from-cyan-500/25 to-slate-900 shadow-[0_0_20px_rgba(0,242,254,0.3)] ring-1 ring-cyan-400 text-left transition-all cursor-pointer relative overflow-hidden"
                >
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-black text-white tracking-tight">Free Trial</span>
                    <span className="text-[9px] px-1.5 py-0.5 rounded bg-cyan-500 text-slate-950 font-black">
                      ACTIVE
                    </span>
                  </div>
                  <div className="text-lg font-black text-cyan-300 mt-1">
                    $0 <span className="text-[10px] text-slate-400 font-normal">forever</span>
                  </div>
                  <div className="text-[10px] text-cyan-200 font-semibold mt-0.5">3 Free AI Scans</div>
                </button>

                {/* 2. Pro Card - DISABLED / LOCKED */}
                <div
                  className="p-3 rounded-2xl border border-white/5 bg-slate-900/30 opacity-40 cursor-not-allowed select-none text-left relative overflow-hidden"
                  title="Subscription billing temporarily disabled during community preview"
                >
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-slate-400">Pro Plan</span>
                    <span className="flex items-center gap-1 text-[8px] font-mono uppercase font-bold px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 border border-white/10">
                      <Lock size={10} /> Locked
                    </span>
                  </div>
                  <div className="text-lg font-black text-slate-500 mt-1">
                    $19<span className="text-[10px] text-slate-600 font-normal">/mo</span>
                  </div>
                  <div className="text-[10px] text-slate-500 mt-0.5">50 Scans • 5 Repos</div>
                </div>

                {/* 3. Enterprise Card - DISABLED / LOCKED */}
                <div
                  className="p-3 rounded-2xl border border-white/5 bg-slate-900/30 opacity-40 cursor-not-allowed select-none text-left relative overflow-hidden"
                  title="Subscription billing temporarily disabled during community preview"
                >
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-slate-400">Enterprise</span>
                    <span className="flex items-center gap-1 text-[8px] font-mono uppercase font-bold px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 border border-white/10">
                      <Lock size={10} /> Locked
                    </span>
                  </div>
                  <div className="text-lg font-black text-slate-500 mt-1">
                    $79<span className="text-[10px] text-slate-600 font-normal">/mo</span>
                  </div>
                  <div className="text-[10px] text-slate-500 mt-0.5">Unlimited • 1-on-1</div>
                </div>
              </div>

              <div className="text-center pt-1 text-[11px] text-cyan-300/90 font-medium">
                ✨ Free Trial: 3 Full AI Security Scans • Instant Access • No Card Required
              </div>
            </div>
          )}

          {err && (
            <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 px-4 py-2.5 text-xs text-rose-300 font-semibold flex items-center gap-2">
              <AlertCircle size={14} className="shrink-0 text-rose-400" />
              <span>{err}</span>
            </div>
          )}

          <button
            type="submit"
            disabled={busy}
            className="btn-primary w-full justify-center py-3 text-xs font-extrabold shadow-glow hover:scale-[1.01] active:scale-[0.99] transition-all cursor-pointer mt-2"
          >
            {busy && <Loader2 size={15} className="animate-spin" />}
            {busy
              ? (mode === 'login' ? 'Authenticating...' : 'Creating Account...')
              : (mode === 'login'
                  ? 'Sign In to Operations Center'
                  : 'Create Free Account & Start Testing (3 Free Scans)')}
          </button>
        </form>
      </div>
    </div>
  )
}
